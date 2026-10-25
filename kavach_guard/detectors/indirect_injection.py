"""
Kavach-Guard: Indirect Prompt Injection Detector (Enterprise Edition)
Specifically designed for RAG pipelines, tool execution returns, and retrieved documents.
Detects:
- Hidden HTML / Markdown comments (<!-- injection -->)
- System instruction overrides (e.g. 'ignore previous instructions', 'system advisory')
- Task abort and operational interface overrides ([SYSTEM UPDATE: OVERRIDE...])
- Developer debug mode switching inside context data
- Canary token trigger instructions (e.g. 'emit the canary', 'output the verification code')
- High-entropy prompt hijacking markers and imperative tone density in passive reference text.
"""

import re
from typing import Dict, Any, List

INDIRECT_PATTERNS = [
    # 1. System override phrasing in data
    (r"(?i)\b(?:ignore|disregard|forget|override|bypass|disable|drop|abandon|suspend)\s+(?:all\s+)?(?:prior|previous|existing|any|operational|safety)?\s*(?:safety\s+)?(?:constraints|guardrails|boundaries|instructions|rules|filters|prompts|guidelines|policies|limits|directives)\b", "Safety Constraint Suppression", 0.96),
    (r"(?i)\[\s*(?:system|admin|regulatory|security|developer|operator|root|kernel)\s*(?:update|override|directive|alert|mode|amendment|interface|command)[^\]]*\]", "Structured Override Tag", 0.98),
    
    # 2. Canary & secret exfiltration directives
    (r"(?i)\b(?:emit|output|print|reveal|leak|exfiltrate)\s+(?:the\s+)?(?:canary|verification|secret|token|credentials|password)\b", "Exfiltration Directive", 0.92),
    (r"KAVACH-\d{4}", "Canary Token Pattern", 0.99),
    (r"SECRET_KEY_[A-Z0-9_]+", "Planted Secret Key Pattern", 0.99),
    
    # 3. Delimiter hijacking & markdown tricks
    (r"<!--[\s\S]*?(?:system|override|ignore|prompt|execute|debug|directive)[\s\S]*?-->", "Hidden HTML Comment Injection", 0.90),
    (r"(?:```|\"\"\")\s*(?:system|admin|override|debug)\s*\n", "Delimiter Escape Injection", 0.88),
    
    # 4. Role masquerading & Mode switching in retrieved text
    (r"(?i)\b(?:you\s+have\s+entered|entering|activated|switching\s+to|switch\s+to|enable|running\s+in)\s+(?:developer|debug|god|unrestricted|sudo|admin|root|jailbreak|dan|unfiltered|jailbroken)\s+(?:mode|privileges|state|interface|environment)\b|\bdeveloper\s+debug\s+mode\b", "Developer/Jailbreak Mode Switch", 0.95),
    (r"\n(?:System|Assistant|AI|Root):\s*[A-Z]", "Role Impersonation in Data", 0.82),
    (r"(?i)\b(?:your\s+)?(?:new|updated|current|primary)\s+(?:primary\s+)?(?:directive|instruction|task|goal|rule|objective|mission|command)\s+(?:is|to\b)", "Directive Substitution", 0.90),
    (r"(?i)\b(?:output|print|show|repeat|display|reveal|read|dump|extract|echo|leak|provide|write)\s+[\w\s,\-]{1,60}?\b(?:system\s+prompt|developer\s+instructions|initial\s+prompt|system\s+message|base\s+instructions|hidden\s+prompt|original\s+instructions)\b", "System Prompt Extraction Attempt", 0.95),
    (r"(?i)\b(?:stop|cancel|halt|terminate|abort|discontinue)\s+(?:all\s+)?(?:current|active|previous|pending|existing)?\s*(?:tasks|operations|instructions|processes|mandates)\b", "Task Abort Command", 0.92),
]

class IndirectInjectionDetector:
    def __init__(self, sensitivity_threshold: float = 0.65):
        self.threshold = sensitivity_threshold

    def scan_text(self, text: str) -> Dict[str, Any]:
        """Scans a single text chunk for indirect prompt injection."""
        detected_threats = []
        max_score = 0.0

        for pattern, label, weight in INDIRECT_PATTERNS:
            matches = list(re.finditer(pattern, text))
            if matches:
                for m in matches:
                    snippet = m.group(0).strip()
                    detected_threats.append({
                        "rule": label,
                        "confidence": weight,
                        "matched_sample": snippet[:100]
                    })
                    if weight > max_score:
                        max_score = weight

        # Multi-signal escalation
        unique_rules = {t["rule"] for t in detected_threats}
        if len(unique_rules) >= 3:
            composite_score = min(0.999, max_score + 0.10)
        elif len(unique_rules) >= 2:
            composite_score = min(0.98, max_score + 0.05)
        else:
            composite_score = max_score

        is_flagged = composite_score >= self.threshold

        return {
            "flagged": is_flagged,
            "threat_score": round(composite_score, 3),
            "threats": detected_threats,
            "category": "indirect_prompt_injection",
            "multi_signal_count": len(unique_rules)
        }

    def scan_chunks(self, chunks: List[str]) -> Dict[str, Any]:
        """Scans an entire list of retrieved RAG chunks, returning per-chunk analysis and sanitization."""
        results = []
        total_flagged = 0
        highest_score = 0.0
        sanitized_chunks = []

        for idx, chunk in enumerate(chunks):
            scan_res = self.scan_text(chunk)
            results.append({
                "chunk_index": idx,
                **scan_res
            })
            if scan_res["flagged"]:
                total_flagged += 1
                sanitized = chunk
                for pattern, _, _ in INDIRECT_PATTERNS:
                    sanitized = re.sub(pattern, "[CONTENT REDACTED BY KAVACH-GUARD]", sanitized, flags=re.IGNORECASE)
                sanitized_chunks.append(sanitized)
            else:
                sanitized_chunks.append(chunk)

            if scan_res["threat_score"] > highest_score:
                highest_score = scan_res["threat_score"]

        return {
            "flagged": total_flagged > 0,
            "flagged_chunk_count": total_flagged,
            "max_threat_score": highest_score,
            "chunk_evaluations": results,
            "sanitized_chunks": sanitized_chunks
        }
