"""
KAVACH v2 - Layer 3: Context-Aware Security Analysis & Task-Alignment Engine
Implements algorithmic context analysis to distinguish legitimate quotations/research
from active prompt-injection exploits, and evaluates task-alignment between
authorized user objectives and retrieved candidate content.

Core Algorithm:
1. Structural Quotation Analysis:
   - Identifies grammatical framing: whether suspicious imperative directives are
     enclosed in quotes, prefixed by interrogative/analytical framing ("explain why...",
     "analyze this example..."), or asserted as direct operational commands.
2. Authority & Source Boundary Check:
   - Evaluates whether the content originates from an untrusted source (retrieved_document,
     user_prompt) while claiming system/developer instruction authority.
3. Task-Alignment Assessment:
   - Evaluates whether instructions inside candidate content align with the authorized
     user task (e.g., answering a banking question vs uploading private records or exfiltrating keys).
4. Decision Synthesis:
   - Emits structured decision: ALLOW, REVIEW, FLAG, BLOCK with detailed rationale.
"""

import re
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class ContextAnalysisResult(BaseModel):
    decision: str  # "ALLOW", "REVIEW", "FLAG", "BLOCK"
    task_alignment: str  # "aligned", "divergent", "adversarial_override", "unrelated"
    is_quotation_or_discussion: bool = False
    source_authority_valid: bool = True
    risk_level: str = "low"  # "low", "medium", "high", "critical"
    rationale: str
    reasons: List[str] = Field(default_factory=list)
    confidence: float = 1.0


# Analytical and research framing markers (interrogative / meta-analysis)
ANALYTICAL_FRAMING_PATTERNS = [
    r"(?i)\b(?:explain|analyze|examine|investigate|study|describe|discuss|clarify)\b",
    r"(?i)\b(?:why\s+is|what\s+makes|how\s+does|what\s+is\s+the\s+meaning\s+of)\b",
    r"(?i)\b(?:example\s+of|sample\s+of|case\s+study|historical\s+incident)\b",
    r"(?i)\b(?:is\s+it\s+true\s+that|vulnerability\s+research|academic\s+paper)\b",
]

# Quoted text extractors: double quotes, single quotes, code blocks, or markdown quotes
QUOTATION_EXTRACTORS = [
    r'\"([^\"]{5,500})\"',
    r'\'([^\']{5,500})\'',
    r'```[\w]*\n([\s\S]{5,500})```',
    r'^[>\s]+(.+)$',
]

# High-risk side-channel / out-of-band actions that almost never align with read queries
OUT_OF_BAND_ACTION_PATTERNS = [
    r"(?i)\b(?:upload|export|send|post|transmit|exfiltrate|leak|dump)\b.*?\b(?:customer|record|private|database|account|secret|credential|canary)\b",
    r"(?i)\b(?:execute|run|eval)\s+(?:command|script|shell|bash|powershell|code|binary|process)\b|\b(?:os\.system|child_process|eval\(|exec\()\b",
    r"(?i)\b(?:transfer\s+funds|send\s+money|debit\s+account|change\s+password|update\s+kyc)\b",
    r"(?i)\b(?:ignore|disregard|override|supersede)\s+.*?\b(?:instruction|system\s+prompt|safety|guardrail)\b",
]


def extract_quotations(text: str) -> List[str]:
    """Extracts quoted blocks from text."""
    quotes = []
    for pattern in QUOTATION_EXTRACTORS:
        for match in re.finditer(pattern, text, re.MULTILINE):
            quotes.append(match.group(1).strip())
    return quotes


def check_is_quotation_or_discussion(text: str, suspicious_snippets: List[str]) -> bool:
    """
    Algorithmic test for whether suspicious text appears as an object of discussion
    rather than an active command.
    Checks:
    1. If the entire text contains analytical inquiry markers.
    2. If the suspicious directive appears inside quotes or code spans.
    3. If the dominant grammatical clause is interrogative/evaluative rather than imperative.
    """
    if not text:
        return False

    has_analytical_framing = any(re.search(p, text) for p in ANALYTICAL_FRAMING_PATTERNS)
    quotes = extract_quotations(text)

    # Check if suspicious material is strictly inside extracted quotations
    quoted_attack = False
    if suspicious_snippets and quotes:
        for snippet in suspicious_snippets:
            snippet_clean = snippet.strip()
            if any(snippet_clean in q or q in snippet_clean for q in quotes):
                quoted_attack = True
                break

    # If framed analytically and quoted, or text explicitly asks about an attack pattern
    if has_analytical_framing and (quoted_attack or len(quotes) > 0):
        return True

    # Check for direct meta-phrasing: "why the phrase 'X' is considered"
    if re.search(r"(?i)\bwhy\s+(?:the\s+phrase|is|would|do)\b.*?\b(?:considered|called|an\s+attack|prompt\s+injection)\b", text):
        return True

    return False


def evaluate_task_alignment(
    user_request: str,
    candidate_content: str,
    content_source: str
) -> Dict[str, Any]:
    """
    Evaluates whether instructions found in candidate content serve the legitimate
    user task, or attempt to divert into unauthorized actions.
    """
    reasons = []
    task_alignment = "aligned"

    # 1. Check if candidate content contains out-of-band side-effect commands
    for pattern in OUT_OF_BAND_ACTION_PATTERNS:
        match = re.search(pattern, candidate_content)
        if match:
            # Check if user explicitly asked for this operation
            user_has_similar_intent = bool(re.search(pattern, user_request))
            if not user_has_similar_intent:
                reasons.append(
                    f"Candidate content from '{content_source}' contains unprompted operational directive: '{match.group(0)[:60]}...'"
                )
                task_alignment = "adversarial_override" if content_source != "user_prompt" else "divergent"

    # 2. Check for instruction authority elevation in untrusted content
    if content_source in ("retrieved_document", "tool_result"):
        if re.search(r"(?i)\b(?:system\s+directive|new\s+rule|must\s+now|override\s+all|your\s+real\s+task)\b", candidate_content):
            reasons.append(
                f"Untrusted data source '{content_source}' attempted to issue system-level governing directives"
            )
            task_alignment = "adversarial_override"

    return {
        "alignment": task_alignment,
        "reasons": reasons
    }


def analyze_context(
    user_request: str,
    candidate_content: str,
    content_source: str = "user_prompt",
    trust_level: str = "untrusted_user",
    task_context: Optional[Dict[str, Any]] = None,
    preliminary_findings: Optional[Dict[str, Any]] = None
) -> ContextAnalysisResult:
    """
    Orchestrates multi-signal context-aware security analysis.
    Distinguishes quotations/research from active attacks, validates authority,
    and checks task alignment.
    """
    reasons: List[str] = []
    prelim = preliminary_findings or {}
    suspicious_snippets = []

    # Extract suspicious snippets from preliminary rule matches if present
    for match in prelim.get("matches", []):
        if hasattr(match, "matched_text"):
            suspicious_snippets.append(match.matched_text)
        elif isinstance(match, dict) and "matched_text" in match:
            suspicious_snippets.append(match["matched_text"])

    # 1. Authority validation
    source_authority_valid = True
    if trust_level in ("untrusted_data", "untrusted_retrieved", "untrusted_user"):
        # Cannot assign instruction authority or claim system priority
        if re.search(r"(?i)\[\s*(?:system|admin|regulatory|security|developer)\s*(?:update|override)[^\]]*\]", candidate_content):
            source_authority_valid = False
            reasons.append(f"Untrusted source '{content_source}' attempted system header spoofing.")

    # 2. Quotation / Educational analysis
    is_quotation = check_is_quotation_or_discussion(user_request, suspicious_snippets)
    if is_quotation:
        reasons.append("Input exhibits analytical framing or quoted security discussion rather than active execution command.")

    # 3. Task alignment
    alignment_eval = evaluate_task_alignment(user_request, candidate_content, content_source)
    task_alignment = alignment_eval["alignment"]
    reasons.extend(alignment_eval["reasons"])

    # 4. Decision Synthesis
    # Case A: Educational / Quoted discussion with no active side-effects
    if is_quotation and task_alignment == "aligned" and source_authority_valid:
        return ContextAnalysisResult(
            decision="REVIEW" if prelim.get("threat_score", 0.0) > 0.7 else "ALLOW",
            task_alignment="aligned",
            is_quotation_or_discussion=True,
            source_authority_valid=True,
            risk_level="low",
            rationale="Content identified as benign educational discussion or security inquiry.",
            reasons=reasons,
            confidence=0.90
        )

    # Case B: Adversarial override in retrieved document (Indirect Prompt Injection)
    if task_alignment == "adversarial_override" or not source_authority_valid:
        return ContextAnalysisResult(
            decision="BLOCK",
            task_alignment=task_alignment,
            is_quotation_or_discussion=False,
            source_authority_valid=False,
            risk_level="critical",
            rationale="Untrusted content contains unaligned directives or authority spoofing.",
            reasons=reasons,
            confidence=0.95
        )

    # Case C: Divergent user request or high preliminary rule matches
    if task_alignment == "divergent" or prelim.get("threat_score", 0.0) >= 0.85:
        return ContextAnalysisResult(
            decision="BLOCK",
            task_alignment=task_alignment,
            is_quotation_or_discussion=is_quotation,
            source_authority_valid=source_authority_valid,
            risk_level="high",
            rationale="High threat score with active imperative directives.",
            reasons=reasons,
            confidence=0.90
        )

    # Case D: Medium ambiguity
    if prelim.get("threat_score", 0.0) >= 0.50:
        return ContextAnalysisResult(
            decision="FLAG",
            task_alignment=task_alignment,
            is_quotation_or_discussion=is_quotation,
            source_authority_valid=source_authority_valid,
            risk_level="medium",
            rationale="Moderate threat indicators detected; flagged for downstream containment.",
            reasons=reasons,
            confidence=0.85
        )

    # Case E: Normal aligned benign content
    return ContextAnalysisResult(
        decision="ALLOW",
        task_alignment="aligned",
        is_quotation_or_discussion=is_quotation,
        source_authority_valid=True,
        risk_level="low",
        rationale="Content is well-aligned with task context.",
        reasons=reasons,
        confidence=0.95
    )
