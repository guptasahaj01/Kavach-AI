"""
KAVACH v2 - Central Security Decision Engine
Orchestrates Defense-in-Depth AI Security:
- Layer 1: Deterministic Security Scanner & Normalizer
- Layer 2: Local Pretrained ML Injection Classifier (ModelManager)
- Layer 3: Context-Aware Security & Task-Alignment Analysis
- Layer 4: Provenance-Aware RAG Protection & Isolation
- Layer 5: Deterministic Runtime Tool Security Policy
- Layer 6: Output Validation & Secrets Masking
- Cross-Cutting: Asynchronous SQLite Audit Persistence
"""

import time
import uuid
import asyncio
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field

from kavach_guard.detectors.rule_engine import RuleEngine, RuleEngineResult
from kavach_guard.detectors.normalizer import normalize_input, MAX_INPUT_LENGTH
from kavach_guard.detectors.model_manager import DEFAULT_THRESHOLD
from kavach_guard.detectors.model_manager import get_model_manager, ModelManager, MLInferenceResult
from kavach_guard.detectors.context_analyzer import analyze_context, ContextAnalysisResult
from kavach_guard.rag_provenance import RAGProvenanceProtector, ProvenanceChunk, RAGInspectionResult
from kavach_guard.tool_security import ToolPolicyEngine, ToolAuthorizationRequest, ToolAuthorizationDecision
from kavach_guard.output_validator import OutputValidator, OutputValidationResult
from kavach_guard.detectors.pii_secrets import PIISecretDetector
from kavach_guard.db import log_inspection, log_tool_authorization, init_db


class SecurityAnalysisRequest(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_INPUT_LENGTH)
    source: Literal["user_prompt", "retrieved_document", "tool_result"] = "user_prompt"  # "user_prompt", "retrieved_document", "tool_result"
    task_context: Optional[str] = None
    threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    caller_role: str = "public_user"
    caller_id: Optional[str] = None


class SecurityAnalysisResponse(BaseModel):
    decision: str  # "ALLOW", "FLAG", "REVIEW", "BLOCK"
    risk_level: str  # "low", "medium", "high", "critical"
    threat_score: float
    attack_categories: List[str] = Field(default_factory=list)
    detectors: Dict[str, Any] = Field(default_factory=dict)
    latency_ms: float
    explanation: str
    policy_version: str = "v2"
    request_id: str
    proceed: bool = False
    coverage_complete: bool = True
    policy_rule: str = ""
    score_kind: str = "uncalibrated_detector_evidence"


class KavachSecurityEngine:
    def __init__(self, ml_model_id: Optional[str] = None):
        self.rule_engine = RuleEngine()
        self.model_manager = get_model_manager(model_id=ml_model_id)
        self.rag_protector = RAGProvenanceProtector(
            rule_engine=self.rule_engine,
            inspector=lambda content, query: self.analyze(SecurityAnalysisRequest(
                content=content, source="retrieved_document", task_context=query
            ))
        )
        self.tool_policy = ToolPolicyEngine()
        self.output_validator = OutputValidator()
        self.pii_detector = PIISecretDetector()

        # In-memory fast audit cache
        self.recent_audits: List[Dict[str, Any]] = []

    def analyze(self, req: SecurityAnalysisRequest) -> SecurityAnalysisResponse:
        """
        Executes end-to-end multi-layer security analysis:
        Input -> L1 Normalization & Rules -> L2 ML Classification -> L3 Context Analysis -> Decision
        """
        start_time = time.perf_counter()
        req_id = f"REQ_{uuid.uuid4().hex[:8].upper()}"
        text = req.content
        normalized = normalize_input(text)
        threshold = req.threshold if req.threshold is not None else DEFAULT_THRESHOLD

        # ----------------------------------------------------
        # Layer 1: Deterministic Scanner & Normalization (< 2ms)
        # ----------------------------------------------------
        t0 = time.perf_counter()
        rule_res: RuleEngineResult = self.rule_engine.scan(text, source_type=req.source)
        l1_latency = round((time.perf_counter() - t0) * 1000, 2)

        # ----------------------------------------------------
        # Layer 2: Pretrained ML Classifier (DeBERTa)
        # ----------------------------------------------------
        t0 = time.perf_counter()
        ml_results = [self.model_manager.predict_single(text, threshold=threshold)]
        if normalized.canonical_text != text:
            ml_results.append(self.model_manager.predict_single(normalized.canonical_text, threshold=threshold))
        ml_res: MLInferenceResult = max(ml_results, key=lambda result: result.injection_score)
        coverage_complete = (not normalized.truncated and all(
            result.status == "completed" and not result.truncated for result in ml_results
        ))
        l2_latency = round((time.perf_counter() - t0) * 1000, 2)

        # ----------------------------------------------------
        # Layer 3: Context-Aware Security Analysis
        # ----------------------------------------------------
        t0 = time.perf_counter()
        context_res: ContextAnalysisResult = analyze_context(
            user_request=req.task_context or text,
            candidate_content=normalized.canonical_text,
            content_source=req.source,
            trust_level="untrusted_user" if req.source == "user_prompt" else "untrusted_data",
            preliminary_findings=rule_res.model_dump()
        )
        l3_latency = round((time.perf_counter() - t0) * 1000, 2)

        # ----------------------------------------------------
        # Transparent Decision Synthesis
        # ----------------------------------------------------
        categories = set(rule_res.categories_detected)
        if ml_res.predicted_label == "INJECTION":
            categories.add("semantic_intent_injection")

        # Evidence remains separate from the enforcement action. Only ALLOW may
        # proceed; unavailable or partial inspection cannot establish safety.
        if "canary_exfiltration" in categories or "secret_leakage" in categories:
            decision, risk_level, policy_rule = "BLOCK", "critical", "sensitive_token"
            explanation = "Canary or authorization-secret pattern detected."
        elif context_res.decision == "BLOCK":
            decision, risk_level, policy_rule = "BLOCK", context_res.risk_level, "active_instruction"
            explanation = context_res.rationale
        elif not coverage_complete:
            decision, risk_level, policy_rule = "REVIEW", "medium", "incomplete_inspection"
            explanation = "Inspection was unavailable, failed, or truncated; processing is held for review."
        elif context_res.is_quotation_or_discussion and context_res.task_alignment == "aligned":
            decision, risk_level, policy_rule = "ALLOW", "low", "quoted_discussion"
            explanation = "Attack-like directives occur only within explicit educational quotations."
        elif ml_res.injection_score >= threshold:
            decision, risk_level, policy_rule = "BLOCK", "high", "semantic_threshold"
            explanation = f"Semantic injection evidence exceeds the configured threshold ({threshold:.2f})."
        elif rule_res.recommended_action in ("block", "flag", "review"):
            decision = rule_res.recommended_action.upper()
            risk_level = "high" if decision == "BLOCK" else "medium"
            policy_rule = "deterministic_findings"
            explanation = "Deterministic findings require containment or review."
        elif context_res.decision in ("FLAG", "REVIEW"):
            decision, risk_level, policy_rule = context_res.decision, "medium", "context_review"
            explanation = context_res.rationale
        else:
            decision, risk_level, policy_rule = "ALLOW", "low", "inspection_passed"
            explanation = "No injection indicators detected in the inspected content."

        composite_score = max(rule_res.threat_score, *(result.injection_score for result in ml_results))

        total_latency = round((time.perf_counter() - start_time) * 1000, 2)

        resp = SecurityAnalysisResponse(
            decision=decision,
            risk_level=risk_level,
            threat_score=round(composite_score, 3),
            attack_categories=sorted(list(categories)),
            detectors={
                "rules": {
                    "status": "completed",
                    "findings_count": len(rule_res.matches),
                    "matches": [m.model_dump() for m in rule_res.matches],
                    "latency_ms": l1_latency,
                    "normalization": rule_res.normalization_meta
                },
                "ml": {
                    "status": ml_res.status,
                    "model": ml_res.model_id,
                    "predicted_label": ml_res.predicted_label,
                    "score": ml_res.injection_score,
                    "latency_ms": l2_latency,
                    "truncated": ml_res.truncated,
                    "device": ml_res.device,
                    "threshold": threshold,
                    "views": [result.model_dump() for result in ml_results]
                },
                "context": {
                    "status": "completed",
                    "task_alignment": context_res.task_alignment,
                    "is_educational": context_res.is_quotation_or_discussion,
                    "latency_ms": l3_latency,
                    "reasons": context_res.reasons
                }
            },
            latency_ms=total_latency,
            explanation=explanation,
            policy_version="v2",
            request_id=req_id,
            proceed=decision == "ALLOW",
            coverage_complete=coverage_complete,
            policy_rule=policy_rule
        )

        # Store in fast memory cache
        audit_entry = resp.model_dump()
        # Shared diagnostic history must not retain source excerpts or private data.
        for match in audit_entry.get("detectors", {}).get("rules", {}).get("matches", []):
            match.pop("matched_text", None)
        audit_entry.get("detectors", {}).get("context", {}).pop("reasons", None)
        audit_entry["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.recent_audits.insert(0, audit_entry)
        if len(self.recent_audits) > 100:
            self.recent_audits.pop()

        return resp

    # ----------------------------------------------------
    # Backward Compatibility Methods for v1 Routes
    # ----------------------------------------------------
    def inspect_messages(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """Backward-compatible Lakera-style inspect endpoint."""
        start = time.perf_counter()
        flagged = False
        categories = {"prompt_injection": False, "indirect_injection": False, "sensitive_data": False}
        details = []

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            req = SecurityAnalysisRequest(content=content, source="user_prompt" if role == "user" else "retrieved_document")
            res = self.analyze(req)
            if not res.proceed:
                flagged = True
                if role == "user":
                    categories["prompt_injection"] = True
                else:
                    categories["indirect_injection"] = True
                details.append({
                    "role": role,
                    "decision": res.decision,
                    "risk_level": res.risk_level,
                    "explanation": res.explanation
                })

        lat = round((time.perf_counter() - start) * 1000, 2)
        return {
            "flagged": flagged,
            "categories": categories,
            "details": details,
            "latency_ms": lat
        }

    def inspect_rag_pipeline(
        self,
        query: str,
        retrieved_chunks: List[str],
        system_prompt: str = "",
        defense_mode: str = "sandwich"
    ) -> Dict[str, Any]:
        """Inspects RAG pipeline using Layer 4 Provenance Isolation."""
        prov_chunks = [
            self.rag_protector.create_provenance_chunk(
                document_id=f"DOC_{idx+1:03d}",
                chunk_id=f"DOC_{idx+1:03d}_C01",
                source_name=f"retrieved_chunk_{idx+1}.txt",
                content=chunk
            )
            for idx, chunk in enumerate(retrieved_chunks)
        ]
        rag_res: RAGInspectionResult = self.rag_protector.inspect_and_contain(
            chunks=prov_chunks,
            user_query=query,
            defense_mode=defense_mode
        )
        return {
            "query": query,
            "flagged_chunks": rag_res.flagged_chunks_count,
            "total_chunks": rag_res.total_chunks,
            "is_contained": rag_res.is_contained,
            "quarantined_ids": rag_res.quarantined_chunk_ids,
            "assembled_prompt": rag_res.assembled_context,
            "defense_mode": rag_res.defense_mode,
            "evaluations": [item.model_dump() for item in rag_res.evaluations],
            "boundary_defense_applied": rag_res.boundary_defense_applied
        }


# Global singleton security engine
_kavach_security_engine: Optional[KavachSecurityEngine] = None

def get_security_engine() -> KavachSecurityEngine:
    global _kavach_security_engine
    if _kavach_security_engine is None:
        _kavach_security_engine = KavachSecurityEngine()
    return _kavach_security_engine
