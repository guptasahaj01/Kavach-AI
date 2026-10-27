"""
KAVACH v2 - Production FastAPI Security Gateway Server
Implements documented v1 and v2 API specification:
- GET  /health & GET /api/v1/security/status
- POST /api/v1/security/analyze
- POST /api/v1/security/analyze-document
- POST /api/v1/security/authorize-tool
- POST /api/v1/rag/query
- POST /api/v1/benchmark/smoke
- GET  /api/v1/benchmark/runs
- GET  /api/v1/metrics/summary
- GET  /api/v1/config/public
- POST /v2/guard (Lakera backward compatibility)
- POST /v2/inspect_rag
- POST /v2/simulate_attack
- GET  /api/benchmark/table
- WebSocket /ws/telemetry
"""

import os
import json
import time
import asyncio
import pandas as pd
from typing import List, Dict, Any, Optional, Literal
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Depends, Response
from starlette.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from kavach_guard.engine import (
    get_security_engine,
    SecurityAnalysisRequest,
    SecurityAnalysisResponse
)
from kavach_guard.rag_provenance import ProvenanceChunk, RAGInspectionResult
from kavach_guard.tool_security import ToolAuthorizationRequest, ToolAuthorizationDecision, ToolDispatcher, build_task_scope
from kavach_guard.auth import Principal, get_principal
from kavach_guard.runtime import ProtectedQuery, ProtectedRuntime, TaskAuthorizationError
from kavach_guard.output_validator import OutputValidator, OutputValidationResult
from kavach_guard.db import (
    init_db,
    log_inspection,
    log_tool_authorization,
    get_recent_inspections,
    get_security_metrics_summary
)
from kavach_guard.db import log_workflow, get_workflow_runs
from kavach_benchmark.prompt_builder import build_rag_prompt
from kavach_benchmark.llm_backend import get_backend
from kavach_benchmark.vector_rag import VectorRAG
from kavach_benchmark.guardrail import OutputGuardrail
from kavach_benchmark.baselines import BaselineEvaluator
from kavach_benchmark.smoke_test import run_smoke_benchmark

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    try:
        await run_in_threadpool(engine.model_manager.initialize)
    except Exception:
        pass
    yield

app = FastAPI(
    title="KAVACH v2 Security Gateway",
    description="Context-Aware, Provenance-Driven AI Security Gateway for LLMs and RAG Pipelines",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("KAVACH_ALLOWED_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173").split(",") if origin.strip()],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = get_security_engine()
runtime = ProtectedRuntime(engine)
tool_dispatcher = ToolDispatcher(policy=engine.tool_policy)
connected_websockets: List[WebSocket] = []

async def broadcast_telemetry(event: Dict[str, Any]):
    for ws in list(connected_websockets):
        try:
            await ws.send_json(event)
        except Exception:
            if ws in connected_websockets:
                connected_websockets.remove(ws)


# --------------------------------------------------------------------------
# Request / Response Schemas
# --------------------------------------------------------------------------
class AnalyzeDocumentRequest(BaseModel):
    document_id: str
    chunk_id: str
    source_name: str
    content: str = Field(max_length=65536)
    user_query: Optional[str] = "What is the policy?"
    defense_mode: Literal["none", "instructional", "sandwich", "quarantine", "sanitize_inline"] = "quarantine"

RAGQueryRequest = ProtectedQuery

class ScopedToolRequest(ToolAuthorizationRequest):
    workflow: Literal["public_banking", "own_records", "audit_export"] = "public_banking"

class MessageItem(BaseModel):
    role: str
    content: str

class GuardRequest(BaseModel):
    messages: List[MessageItem]

class RAGInspectRequest(BaseModel):
    query: str
    retrieved_chunks: List[str]
    system_prompt: Optional[str] = ""
    defense_mode: Literal["none", "instructional", "sandwich", "quarantine", "sanitize_inline"] = "sandwich"

class SimulateAttackRequest(BaseModel):
    attack_type: str = "upi_poisoned"
    k: int = Field(default=3, ge=1, le=10)
    chunk_size: int = Field(default=512, ge=64, le=1024)
    hardening: Literal["none", "instructional", "sandwich"] = "sandwich"
    guardrail: Literal["off", "on"] = "on"


# --------------------------------------------------------------------------
# Static Assets Mounts
# --------------------------------------------------------------------------
if os.path.exists("outputs"):
    app.mount("/outputs", StaticFiles(directory="outputs"), name="outputs")

if os.path.exists("frontend/dist/assets"):
    app.mount("/assets", StaticFiles(directory="frontend/dist/assets"), name="assets")


# --------------------------------------------------------------------------
# 1. Health & Status Endpoints
# --------------------------------------------------------------------------
@app.get("/health")
@app.get("/api/health")
def read_health():
    return {
        "status": "healthy" if engine.model_manager.is_available() else "degraded",
        "service": "KAVACH v2 Security Gateway",
        "version": "2.0.0",
        "model": engine.model_manager.model_id,
        "model_status": engine.model_manager.status,
        "device": engine.model_manager.device
    }

@app.get("/api/v1/security/status")
def security_status():
    return {
        "status": "operational" if engine.model_manager.is_available() else "degraded",
        "gateway_version": "2.0.0",
        "generation_backend": {"id": f"{os.getenv('KAVACH_LLM_BACKEND', 'ollama')}/{os.getenv('KAVACH_LLM_MODEL', 'qwen2.5:3b')}", "status": "not_probed", "kind": "real"},
        "enforcement_policy": "v3-task-scoped",
        "active_layers": [
            {"layer": 1, "name": "Deterministic Scanner & Normalizer", "status": "configured"},
            {"layer": 2, "name": "Semantic ML Injection Classifier", "model": engine.model_manager.model_id, "status": engine.model_manager.status},
            {"layer": 3, "name": "Context-Aware & Task-Alignment Analysis", "status": "configured"},
            {"layer": 4, "name": "Provenance-Aware RAG Protection", "status": "configured"},
            {"layer": 5, "name": "Deterministic Runtime Tool Dispatcher", "status": "configured"},
            {"layer": 6, "name": "Output Validation & Leakage Prevention", "status": "configured"}
        ]
    }

@app.get("/api/v1/config/public")
def public_config():
    return {
        "model_id": engine.model_manager.model_id,
        "model_device": engine.model_manager.device,
        "read_only_tools": ["search_public_documents", "retrieve_bank_rates", "summarize_public_policy"],
        "restricted_tools": ["simulated_customer_record_access", "simulated_external_export", "send_external_email", "transfer_funds", "modify_customer_records"],
        "approved_destinations": ["https://api.internal-bank.local/reports", "internal://audit-vault"],
        "supported_baselines": ["B0", "B1", "B2", "B3", "B4", "B5", "B6"]
    }


@app.get("/api/v1/security/identity")
def identity(principal: Principal = Depends(get_principal)):
    workflows = []
    for workflow in ("public_banking", "own_records", "audit_export"):
        try:
            build_task_scope(principal, workflow)
            workflows.append(workflow)
        except ValueError:
            continue
    return {"principal_id": principal.principal_id, "role": principal.role,
            "account_ids": sorted(principal.account_ids), "allowed_destinations": sorted(principal.allowed_destinations),
            "workflows": workflows}


# --------------------------------------------------------------------------
# 2. Live Security Analysis Endpoints
# --------------------------------------------------------------------------
@app.post("/api/v1/security/analyze", response_model=SecurityAnalysisResponse)
async def analyze_endpoint(req: SecurityAnalysisRequest, response: Response):
    """Live prompt analysis evaluating L1-L3 with transparent structured output."""
    res = await run_in_threadpool(engine.analyze, req)

    # Persist to SQLite
    persisted = await log_inspection(
        request_id=res.request_id,
        source=req.source,
        decision=res.decision,
        risk_level=res.risk_level,
        threat_score=res.threat_score,
        latency_ms=res.latency_ms,
        categories=res.attack_categories,
        rules_count=res.detectors.get("rules", {}).get("findings_count", 0),
        ml_label=res.detectors.get("ml", {}).get("predicted_label"),
        ml_score=res.detectors.get("ml", {}).get("score"),
        task_alignment=res.detectors.get("context", {}).get("task_alignment"),
        is_educational=res.detectors.get("context", {}).get("is_educational", False)
    )
    response.headers["X-Kavach-Audit"] = "persisted" if persisted else "unavailable"

    # Broadcast event
    await broadcast_telemetry({
        "type": "security_inspection",
        "timestamp": time.time(),
        "request_id": res.request_id,
        "decision": res.decision,
        "risk_level": res.risk_level,
        "latency_ms": res.latency_ms,
        "threat_score": res.threat_score,
        "source": req.source,
        "explanation": res.explanation
    })

    return res

@app.post("/api/v1/security/analyze-document")
async def analyze_document_endpoint(req: AnalyzeDocumentRequest):
    """Analyzes a single retrieved document chunk with application-controlled provenance."""
    chunk = engine.rag_protector.create_provenance_chunk(
        document_id=req.document_id,
        chunk_id=req.chunk_id,
        source_name=req.source_name,
        content=req.content
    )
    rag_res = await run_in_threadpool(engine.rag_protector.inspect_and_contain,
        [chunk],
        user_query=req.user_query or "Banking query",
        defense_mode=req.defense_mode or "sandwich"
    )
    return {
        "document_id": req.document_id,
        "chunk_id": req.chunk_id,
        "flagged": rag_res.flagged_chunks_count > 0,
        "chunks_evaluation": [c.model_dump() for c in rag_res.evaluations],
        "assembled_prompt": rag_res.assembled_context,
        "is_contained": rag_res.is_contained
    }

@app.post("/api/v1/security/authorize-tool", response_model=ToolAuthorizationDecision)
async def authorize_tool_endpoint(req: ScopedToolRequest, principal: Principal = Depends(get_principal)):
    """Evaluates proposed tool execution against deterministic Layer 5 policies."""
    try:
        scope = build_task_scope(principal, req.workflow)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    decision = engine.tool_policy.authorize(req, principal, scope)

    await log_tool_authorization(
        tool_name=decision.tool_name,
        caller_role=decision.caller_role,
        authorized=decision.authorized,
        policy_code=decision.policy_code,
        decision_reason=decision.decision_reason,
        risk_level=decision.risk_level
    )

    await broadcast_telemetry({
        "type": "tool_authorization",
        "timestamp": time.time(),
        "tool_name": decision.tool_name,
        "authorized": decision.authorized,
        "policy_code": decision.policy_code,
        "caller_role": decision.caller_role,
        "risk_level": decision.risk_level
    })

    return decision

@app.post("/api/v1/tools/execute")
async def execute_tool_endpoint(req: ScopedToolRequest, principal: Principal = Depends(get_principal)):
    try:
        scope = build_task_scope(principal, req.workflow)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    execution = await run_in_threadpool(tool_dispatcher.execute, req, principal, scope)
    result = execution.model_dump()
    if execution.result is not None:
        import json as json_module
        checked = engine.output_validator.validate(json_module.dumps(execution.result, ensure_ascii=False))
        if not checked.is_safe:
            result["result"] = None
            result["error"] = "Tool output was withheld by disclosure checks"
    persisted = await log_tool_authorization(
        tool_name=execution.decision.tool_name, caller_role=principal.role,
        authorized=execution.decision.authorized, policy_code=execution.decision.policy_code,
        decision_reason=execution.decision.decision_reason, risk_level=execution.decision.risk_level,
    )
    result["audit_status"] = "persisted" if persisted else "unavailable"
    return result


@app.post("/api/v1/rag/query")
async def rag_query_endpoint(req: RAGQueryRequest, principal: Principal = Depends(get_principal)):
    """Protected workflow: callers cannot disable containment or mint permission."""
    try:
        result = await run_in_threadpool(runtime.run, req, principal)
    except TaskAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    persisted = await log_workflow(result, principal.principal_id)
    result["audit_status"] = "persisted" if persisted else "unavailable"
    await broadcast_telemetry({"type": "protected_workflow", "request_id": result["request_id"],
                               "timestamp": time.time(), "status": result["status"],
                               "latency_ms": result["latency_ms"], "audit_status": result["audit_status"]})
    return result


@app.get("/api/v1/workflow/runs")
async def workflow_runs(limit: int = Query(default=20, ge=1, le=100), principal: Principal = Depends(get_principal)):
    return await get_workflow_runs(principal.principal_id, limit)


# --------------------------------------------------------------------------
# 3. Benchmark Endpoints
# --------------------------------------------------------------------------
@app.post("/api/v1/benchmark/smoke")
def trigger_smoke_benchmark():
    """Executes automated multi-baseline smoke benchmark and returns measured results."""
    try:
        metrics = run_smoke_benchmark()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="The classifier benchmark is unavailable; no measurement was produced.") from None
    return {
        "status": "completed",
        "baselines_evaluated": len(metrics),
        "metrics": [m.model_dump() for m in metrics]
    }

@app.get("/api/v1/benchmark/runs")
def get_benchmark_runs():
    """Returns stored baseline comparison results."""
    json_path = "outputs/baseline_comparison.json"
    if os.path.exists(json_path):
        with open(json_path, "r", encoding="utf-8") as f:
            return [{**row, "metric_type": "detector_classification", "result_kind": "classifier_measurement"}
                    for row in json.load(f)]
    return []

@app.get("/api/v1/metrics/summary")
async def get_metrics_summary():
    """Returns metrics from SQLite database."""
    summary = await get_security_metrics_summary()
    return summary


# --------------------------------------------------------------------------
# 4. Backward Compatibility Endpoints
# --------------------------------------------------------------------------
@app.post("/v2/guard")
async def guard_endpoint(req: GuardRequest):
    msgs = [{"role": m.role, "content": m.content} for m in req.messages]
    result = await run_in_threadpool(engine.inspect_messages, msgs)
    await broadcast_telemetry({
        "type": "guard_event",
        "timestamp": time.time(),
        "flagged": result["flagged"],
        "latency_ms": result["latency_ms"],
        "details": result["details"]
    })
    return result

@app.post("/v2/inspect_rag")
async def inspect_rag_endpoint(req: RAGInspectRequest):
    result = await run_in_threadpool(engine.inspect_rag_pipeline,
        query=req.query,
        retrieved_chunks=req.retrieved_chunks,
        system_prompt=req.system_prompt,
        defense_mode=req.defense_mode
    )
    await broadcast_telemetry({
        "type": "rag_event",
        "timestamp": time.time(),
        "flagged": result.get("flagged", False),
        "flagged_chunks": result.get("flagged_chunks", 0)
    })
    return result

@app.post("/v2/simulate_attack")
async def simulate_attack_endpoint(req: SimulateAttackRequest):
    start = time.perf_counter()
    manifest_path = "data/manifest.json"
    if not os.path.exists(manifest_path):
        raise HTTPException(status_code=400, detail="Corpus manifest not generated yet.")

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    if req.attack_type == "upi_poisoned":
        q_item = manifest["poisoned_queries"][0]
        is_poisoned_trial = True
    elif req.attack_type == "neft_exfiltration":
        q_item = manifest["poisoned_queries"][10]
        is_poisoned_trial = True
    elif req.attack_type == "aadhaar_injection":
        q_item = manifest["poisoned_queries"][40]
        is_poisoned_trial = True
    else:
        q_item = manifest["benign_queries"][0]
        is_poisoned_trial = False

    query = q_item["query"]
    target_doc = q_item.get("target_poisoned_doc", "doc_001_upi_limits_1.txt")

    rag = VectorRAG(chunk_size=req.chunk_size)
    rag.index_corpus("data/corpus")

    if is_poisoned_trial:
        p_path = os.path.join("data/poisoned_corpus", target_doc)
        with open(p_path, "r", encoding="utf-8") as f:
            p_text = f.read()
        retrieved = rag.retrieve_with_poisoned_doc(query, p_text, target_doc, k=req.k)
    else:
        retrieved = rag.retrieve(query, k=req.k)

    retrieved_texts = [c.text for c, s in retrieved]
    has_poisoned_chunk = any(c.is_poisoned for c, s in retrieved)

    # Kavach-Guard Provenance Inspection
    prov_chunks = [
        engine.rag_protector.create_provenance_chunk(
            document_id=f"DOC_{i+1:03d}",
            chunk_id=f"DOC_{i+1:03d}_C01",
            source_name=target_doc if has_poisoned_chunk and i == 0 else f"clean_doc_{i+1}.txt",
            content=text
        )
        for i, text in enumerate(retrieved_texts)
    ]
    rag_scan = engine.rag_protector.inspect_and_contain(prov_chunks, user_query=query, defense_mode=req.hardening)

    # This endpoint intentionally demonstrates simulation and may retain malicious context.
    prompt_data = build_rag_prompt(query, [c.sanitized_content or c.content for c in rag_scan.chunks], hardening=req.hardening)

    # LLM Backend
    backend = get_backend("calibrated")
    llm_resp = backend.generate(
        prompt_data["system_prompt"],
        prompt_data["user_prompt"],
        metadata={
            "hardening": req.hardening,
            "k": req.k,
            "chunk_size": req.chunk_size,
            "has_poisoned_chunk": has_poisoned_chunk,
            "query": query
        }
    )

    # Output Guardrail
    guardrail = OutputGuardrail(enabled=(req.guardrail == "on"))
    g_eval = guardrail.evaluate(llm_resp, is_benign_trial=(not is_poisoned_trial))

    canary_emitted = g_eval["canary_detected"]
    secret_leaked = g_eval["secret_detected"]

    if canary_emitted and not g_eval["blocked"]:
        outcome = "ATTACK_SUCCEEDED"
        verdict = "Simulation: The programmed response contained a canary that passed the configured output checks."
    elif g_eval["blocked"]:
        outcome = "BLOCKED_BY_GUARDRAIL"
        verdict = "Simulation: Output checks blocked the programmed response."
    elif not canary_emitted and has_poisoned_chunk:
        outcome = "NEUTRALIZED_BY_HARDENING"
        verdict = f"Simulation: No canary appeared in the programmed response with {req.hardening} hardening; this does not establish real-model defense effectiveness."
    else:
        outcome = "CLEAN_BENIGN_RESPONSE"
        verdict = "Simulation: A programmed response was produced for the benign scenario; answer accuracy was not independently assessed."

    return {
        "result_kind": "simulation",
        "backend": "calibrated_simulation",
        "scenario": req.attack_type,
        "query": query,
        "k": req.k,
        "chunk_size": req.chunk_size,
        "hardening": req.hardening,
        "guardrail": req.guardrail,
        "has_poisoned_chunk": has_poisoned_chunk,
        "flagged_chunk_count": rag_scan.flagged_chunks_count,
        "retrieved_chunks_preview": [t[:180] + "..." for t in retrieved_texts],
        "system_prompt_used": prompt_data["system_prompt"],
        "llm_response": llm_resp,
        "output_guardrail": g_eval,
        "canary_emitted": canary_emitted,
        "secret_leaked": secret_leaked,
        "outcome": outcome,
        "verdict": verdict,
        "total_latency_ms": round((time.perf_counter() - start) * 1000, 2)
    }

@app.get("/api/benchmark/table")
def get_benchmark_table():
    csv_path = "outputs/table_1_matrix.csv"
    if not os.path.exists(csv_path):
        return []
    df = pd.read_csv(csv_path)
    return [{**row, "result_kind": "simulation"} for row in json.loads(df.to_json(orient="records"))]

@app.get("/api/audit/history")
async def get_audit_history(limit: int = Query(default=50, ge=1, le=100)):
    records = await get_recent_inspections(limit=limit)
    if not records:
        # Fall back to engine memory cache
        return engine.recent_audits[:limit]
    return records


# --------------------------------------------------------------------------
# 5. WebSocket Telemetry
# --------------------------------------------------------------------------
@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)
    try:
        while True:
            # Keepalive ping/pong
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)


# --------------------------------------------------------------------------
# 6. Root Frontend HTML
# --------------------------------------------------------------------------
@app.get("/")
def read_root():
    if os.path.exists("frontend/dist/index.html"):
        return FileResponse("frontend/dist/index.html")
    return {
        "status": "online",
        "service": "KAVACH v2 Security Gateway",
        "version": "2.0.0"
    }
