"""
KAVACH v2 - Layer 1: Deterministic Security Rules Engine
Configurable, structured rule-based scanner supporting:
- Input canonicalization (Unicode, zero-width, homoglyphs, bounded decoders)
- Authority and role impersonation (ROLE_SPOOF_*)
- Task abort & operational overrides (OVERRIDE_*)
- Safety constraint suppression (SUPPRESS_*)
- System prompt extraction (EXTRACT_*)
- Directive substitution (DIRECTIVE_*)
- Delimiter & structure escapes (DELIMITER_*)
- Canary & planted benchmark secrets (CANARY_*, SECRET_*)
- Obfuscation indicators (OBFUSCATION_*)
- Contextual mitigation (distinguishing analytical/explanatory contexts from active attacks)
"""

import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from kavach_guard.detectors.normalizer import normalize_input, NormalizedResult


class RuleMatch(BaseModel):
    rule_id: str
    category: str
    severity: str  # "low", "medium", "high", "critical"
    span_start: int
    span_end: int
    matched_text: str  # Redacted if sensitive
    description: str


class RuleEngineResult(BaseModel):
    detector: str = "rule_engine"
    matches: List[RuleMatch] = Field(default_factory=list)
    recommended_action: str = "allow"  # "allow", "flag", "review", "block"
    threat_score: float = 0.0
    categories_detected: List[str] = Field(default_factory=list)
    normalization_meta: Dict[str, Any] = Field(default_factory=dict)
    is_educational_context: bool = False


# Rule definitions with explicit IDs, category, severity, and regex
STRUCTURED_RULES = [
    # 1. Authority & Role Spoofing
    {
        "id": "ROLE_SPOOF_001",
        "category": "authority_spoofing",
        "severity": "high",
        "pattern": r"(?i)\[\s*(?:system|admin|regulatory|security|developer|operator|root|kernel)\s*(?:update|override|directive|alert|mode|amendment|interface|command)[^\]]*\]",
        "desc": "System header spoofing bracket syntax"
    },
    {
        "id": "ROLE_SPOOF_002",
        "category": "authority_spoofing",
        "severity": "high",
        "pattern": r"(?i)\b(?:you\s+have\s+entered|entering|activated|switching\s+to|switch\s+to|enable|running\s+in)\s+(?:developer|debug|god|unrestricted|sudo|admin|root|jailbreak|dan|unfiltered|jailbroken)\s+(?:mode|privileges|state|interface|environment)\b|\bdeveloper\s+debug\s+mode\b",
        "desc": "Developer/jailbreak mode activation declaration"
    },
    {
        "id": "ROLE_SPOOF_003",
        "category": "authority_spoofing",
        "severity": "high",
        "pattern": r"(?i)\b(?:for\s+the\s+rest\s+of\s+this\s+conversation,\s+)?you\s+are\s+(?:now\s+)?[\"']?(?:UNBOUNDED|DAN|STAN|DUDE|AIM|CHAOS|DARKGPT|DEV_MODE)[\"']?\b",
        "desc": "Persona adoption instruction override"
    },
    {
        "id": "ROLE_SPOOF_004",
        "category": "authority_spoofing",
        "severity": "medium",
        "pattern": r"\n(?:System|Assistant|AI|Root|Developer):\s*[A-Z]",
        "desc": "Pseudo-conversation turn impersonation"
    },

    # 2. Operational Overrides & Task Abort
    {
        "id": "OVERRIDE_001",
        "category": "instruction_override",
        "severity": "critical",
        "pattern": r"(?i)\b(?:stop|cancel|halt|terminate|abort|discontinue)\s+(?:all\s+)?(?:current|active|previous|pending|existing)?\s*(?:tasks|operations|instructions|processes|mandates)\b",
        "desc": "Immediate task cancellation command"
    },
    {
        "id": "DIRECTIVE_001",
        "category": "instruction_override",
        "severity": "high",
        "pattern": r"(?i)\b(?:your\s+)?(?:new|updated|current|primary)\s+(?:primary\s+)?(?:directive|instruction|task|goal|rule|objective|mission|command)\s+(?:is|to\b)",
        "desc": "Directive substitution declaration"
    },

    # 3. Safety Constraint Suppression
    {
        "id": "SUPPRESS_001",
        "category": "constraint_suppression",
        "severity": "high",
        "pattern": r"(?i)\b(?:ignore|disregard|forget|override|bypass|disable|drop|abandon|suspend)\s+(?:all\s+)?(?:prior|previous|existing|any|operational|safety)?\s*(?:safety\s+)?(?:constraints|guardrails|boundaries|instructions|rules|filters|prompts|guidelines|policies|limits|directives)\b",
        "desc": "Explicit safety constraint disregard"
    },
    {
        "id": "SUPPRESS_002",
        "category": "constraint_suppression",
        "severity": "medium",
        "pattern": r"(?i)\b(?:bypass|evade|circumvent)\s+(?:safety|ethical|content|alignment)\s+(?:filters|moderation|safeguards)\b",
        "desc": "Filter evasion directive"
    },

    # 4. System Prompt Extraction
    {
        "id": "EXTRACT_001",
        "category": "system_prompt_extraction",
        "severity": "high",
        "pattern": r"(?i)\b(?:output|print|show|repeat|display|reveal|read|dump|extract|echo|leak|provide|write)\s+[\w\s,\-]{1,60}?\b(?:system\s+prompt|developer\s+instructions|initial\s+prompt|system\s+message|base\s+instructions|hidden\s+prompt|original\s+instructions|instructions\s+set\s+by\s+your\s+creators)\b",
        "desc": "Direct system instruction extraction"
    },
    {
        "id": "PREFIX_FORCE_001",
        "category": "system_prompt_extraction",
        "severity": "medium",
        "pattern": r"(?i)\b(?:start|begin)\s+(?:your\s+)?(?:response|reply|answer|output)\s+with\s+[\'\"].*?[\'\"]",
        "desc": "Prefix forcing attack"
    },

    # 5. Delimiter & Markup Injection
    {
        "id": "DELIMITER_001",
        "category": "delimiter_escape",
        "severity": "medium",
        "pattern": r"<!--[\s\S]*?(?:system|override|ignore|prompt|execute|debug|directive)[\s\S]*?-->",
        "desc": "Hidden HTML comment instruction injection"
    },
    {
        "id": "DELIMITER_002",
        "category": "delimiter_escape",
        "severity": "medium",
        "pattern": r"(?:```|\"\"\")\s*(?:system|admin|override|debug)\s*\n",
        "desc": "Triple delimiter spoofing header"
    },

    # 6. Canary & Secrets Exfiltration Traps
    {
        "id": "CANARY_001",
        "category": "canary_exfiltration",
        "severity": "critical",
        "pattern": r"\bKAVACH-\d{4}\b",
        "desc": "Planted benchmark canary identifier"
    },
    {
        "id": "SECRET_001",
        "category": "secret_leakage",
        "severity": "critical",
        "pattern": r"\bSECRET_KEY_[A-Z0-9_]+\b",
        "desc": "Planted system authorization secret key"
    },
    {
        "id": "CANARY_DIRECTIVE_001",
        "category": "canary_exfiltration",
        "severity": "high",
        "pattern": r"(?i)\b(?:emit|output|print|reveal|leak|exfiltrate)\s+(?:the\s+)?(?:canary|verification|secret|token|credentials|password)\b",
        "desc": "Direct order to exfiltrate secret/canary"
    },
]

# Analytical context indicators (benign discussions, quoting security papers or research)
EDUCATIONAL_INDICATORS = [
    r"(?i)\b(?:analyze|examine|explain|why\s+is|what\s+is|study|discuss|describe|definition\s+of)\b.*?\b(?:jailbreak|prompt\s+injection|vulnerability|exploit|attack)\b",
    r"(?i)\b(?:example\s+of|sample\s+of|case\s+study|historical\s+jailbreak)\b",
    r"(?i)\b(?:why\s+would|how\s+does|how\s+do\s+attackers|why\s+is\s+the\s+phrase)\b",
    r"(?i)\b(?:is\s+it\s+possible\s+to\s+prevent|mitigate|defense\s+against)\b",
]


class RuleEngine:
    def __init__(self, sensitivity: float = 0.65):
        self.sensitivity = sensitivity

    def is_educational_query(self, text: str) -> bool:
        """Determines if query is an educational or research explanation query."""
        for pattern in EDUCATIONAL_INDICATORS:
            if re.search(pattern, text):
                return True
        return False

    def scan(self, text: str, source_type: str = "user_prompt") -> RuleEngineResult:
        """
        Executes bounded normalization, regex screening, severity scoring,
        and contextual action recommendation.
        """
        if not text or not text.strip():
            return RuleEngineResult()

        # Step 1: Input Normalization & Canonicalization
        norm_res: NormalizedResult = normalize_input(text)
        canonical_text = norm_res.canonical_text

        matches: List[RuleMatch] = []
        categories = set()
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}

        # Step 2: Screen with all structured rules
        for r in STRUCTURED_RULES:
            # Check against canonical text
            for m in re.finditer(r["pattern"], canonical_text):
                matched_snippet = m.group(0).strip()
                # For secret/canary, redact value from matched text in logs
                if "SECRET" in r["id"] or "CANARY" in r["id"]:
                    redacted = re.sub(r"[A-Za-z0-9]", "*", matched_snippet)
                else:
                    redacted = matched_snippet[:100]

                match_obj = RuleMatch(
                    rule_id=r["id"],
                    category=r["category"],
                    severity=r["severity"],
                    span_start=m.start(),
                    span_end=m.end(),
                    matched_text=redacted,
                    description=r["desc"]
                )
                matches.append(match_obj)
                categories.add(r["category"])
                severity_counts[r["severity"]] += 1

        # Step 3: Record obfuscation findings from normalizer
        if norm_res.transforms_applied:
            for transform in norm_res.transforms_applied:
                if "DECODED" in transform:
                    matches.append(RuleMatch(
                        rule_id="OBFUSCATION_001",
                        category="payload_obfuscation",
                        severity="medium",
                        span_start=0,
                        span_end=min(len(text), 50),
                        matched_text=f"[{transform}]",
                        description=f"Automated decoding of obfuscated content: {transform}"
                    ))
                    categories.add("payload_obfuscation")
                    severity_counts["medium"] += 1

        # Step 4: Check if text is an educational/research question
        is_educational = self.is_educational_query(canonical_text)

        # Step 5: Compute composite threat score & recommended action
        # Baseline severity weights
        score = 0.0
        score += severity_counts["critical"] * 0.95
        score += severity_counts["high"] * 0.40
        score += severity_counts["medium"] * 0.15
        score += severity_counts["low"] * 0.05
        threat_score = min(0.999, round(score, 3))

        # Decision logic:
        # If critical (canary/secret/task abort) -> BLOCK
        # If educational context and no critical rule -> REVIEW or ALLOW (false-positive resistance!)
        if severity_counts["critical"] > 0:
            recommended_action = "block"
        elif is_educational:
            # Benign explanation or analysis of injection techniques
            if severity_counts["high"] > 0 or severity_counts["medium"] > 0:
                recommended_action = "review"
                threat_score = min(threat_score, 0.45)
            else:
                recommended_action = "allow"
        elif severity_counts["high"] >= 2 or threat_score >= 0.80:
            recommended_action = "block"
        elif severity_counts["high"] >= 1 or severity_counts["medium"] >= 2 or threat_score >= self.sensitivity:
            recommended_action = "flag"
        elif severity_counts["medium"] >= 1:
            recommended_action = "review"
        else:
            recommended_action = "allow"

        return RuleEngineResult(
            detector="rule_engine",
            matches=matches,
            recommended_action=recommended_action,
            threat_score=threat_score,
            categories_detected=sorted(list(categories)),
            normalization_meta={
                "transforms": norm_res.transforms_applied,
                "truncated": norm_res.truncated,
                "original_len": norm_res.original_length,
                "final_len": norm_res.final_length
            },
            is_educational_context=is_educational
        )
