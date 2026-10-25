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
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from kavach_guard.detectors.rule_engine import RuleEngine, RuleEngineResult
from kavach_guard.detectors.model_manager import get_model_manager, ModelManager, MLInferenceResult
from kavach_guard.detectors.context_analyzer import analyze_context, ContextAnalysisResult
from kavach_guard.rag_provenance import RAGProvenanceProtector, ProvenanceChunk, RAGInspectionResult
from kavach_guard.tool_security import ToolPolicyEngine, ToolAuthorizationRequest, ToolAuthorizationDecision
from kavach_guard.output_validator import OutputValidator, OutputValidationResult
from kavach_guard.detectors.pii_secrets import PIISecretDetector
from kavach_guard.db import log_inspection, log_tool_authorization, init_db


class SecurityAnalysisRequest(BaseModel):
    content: str
    source: str = "user_prompt"  # "user_prompt", "retrieved_document", "tool_result"
    task_context: Optional[str] = None
    threshold: Optional[float] = None
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


class KavachSecurityEngine:
    def __init__(self, ml_model_id: Optional[str] = None):
        self.rule_engine = RuleEngine()
        self.model_manager = get_model_manager(model_id=ml_model_id)
        self.rag_protector = RAGProvenanceProtector(rule_engine=self.rule_engine)
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
        ml_res: MLInferenceResult = self.model_manager.predict_single(text)
        l2_latency = round((time.perf_counter() - t0) * 1000, 2)

        # ----------------------------------------------------
        # Layer 3: Context-Aware Security Analysis
        # ----------------------------------------------------
        t0 = time.perf_counter()
        context_res: ContextAnalysisResult = analyze_context(
            user_request=req.task_context or text,
            candidate_content=text,
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

        # Explicit Decision Logic:
        # Rule 1: Planted secrets/canary or critical override command -> Immediate BLOCK
        if "canary_exfiltration" in categories or "secret_leakage" in categories:
            decision = "BLOCK"
            risk_level = "critical"
            explanation = "Planted benchmark canary or system authorization secret detected."

        # Rule 2: Benign educational / research inquiry (False positive resistance!)
        elif context_res.is_quotation_or_discussion and context_res.task_alignment == "aligned":
            if rule_res.recommended_action == "block":
                decision = "REVIEW"
                risk_level = "medium"
                explanation = "Input discusses prompt injection or jailbreak techniques in an analytical/educational context."
            else:
                decision = "ALLOW"
                risk_level = "low"
                explanation = "Analytical/educational discussion of security vulnerabilities verified."

        # Rule 3: Adversarial override in data or authority spoofing -> BLOCK
        elif context_res.decision == "BLOCK":
            decision = "BLOCK"
            risk_level = "critical" if context_res.risk_level == "critical" else "high"
            explanation = context_res.rationale

        # Rule 4: ML model flags injection with high confidence and rule engine flags -> BLOCK
        elif ml_res.status == "completed" and ml_res.predicted_label == "INJECTION" and ml_res.injection_score >= 0.70:
            decision = "BLOCK"
            risk_level = "high"
            explanation = f"Semantic classifier detected high adversarial injection intent (p={ml_res.injection_score:.3f})."

        # Rule 5: Rule engine recommendation was block or flag
        elif rule_res.recommended_action in ("block", "flag"):
            decision = rule_res.recommended_action.upper()
            risk_level = "high" if decision == "BLOCK" else "medium"
            explanation = "Deterministic rule signatures matched known adversarial patterns."

        # Rule 6: Degraded ML status with clean rules -> REVIEW for sensitive contexts, otherwise ALLOW
        elif ml_res.status == "degraded":
            decision = "REVIEW" if rule_res.threat_score > 0.3 else "ALLOW"
            risk_level = "medium" if decision == "REVIEW" else "low"
            explanation = "ML classifier degraded (offline). Scanned using Layer 1 deterministic rules."

        # Default clean
        else:
            decision = "ALLOW"
            risk_level = "low"
            explanation = "No adversarial prompt injection patterns detected."

        # Composite threat score (heuristic synthesis for dashboard display)
        composite_score = max(
            rule_res.threat_score,
            ml_res.injection_score if ml_res.status == "completed" else 0.0
        )
        if decision == "BLOCK":
            composite_score = max(composite_score, 0.90)
        elif decision == "ALLOW":
            composite_score = min(composite_score, 0.25)

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
                    "latency_ms": l1_latency
                },
                "ml": {
                    "status": ml_res.status,
                    "model": ml_res.model_id,
                    "predicted_label": ml_res.predicted_label,
                    "score": ml_res.injection_score,
                    "latency_ms": l2_latency,
                    "truncated": ml_res.truncated,
                    "device": ml_res.device
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
            request_id=req_id
        )

        # Store in fast memory cache
        audit_entry = resp.model_dump()
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
            if res.decision in ("BLOCK", "FLAG"):
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
            "defense_mode": rag_res.defense_mode
        }


# Global singleton security engine
_kavach_security_engine: Optional[KavachSecurityEngine] = None

def get_security_engine() -> KavachSecurityEngine:
    global _kavach_security_engine
    if _kavach_security_engine is None:
        _kavach_security_engine = KavachSecurityEngine()
    return _kavach_security_engine
