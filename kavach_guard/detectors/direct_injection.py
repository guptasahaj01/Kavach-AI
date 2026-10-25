"""
Kavach-Guard: Direct Prompt Injection & Jailbreak Detector (Enterprise Edition)
Screens user-submitted prompts across 7 canonical adversarial intent dimensions:
1. Task Abort / Operational Override commands
2. System Header Spoofing ([SYSTEM UPDATE...], [OVERRIDE...])
3. Persona & Jailbreak Mode Switching (Developer Debug Mode, DAN, Godmode)
4. Safety Constraint Suppression (Ignore guardrails, boundaries, constraints)
5. Directive Substitution (New primary directive is...)
6. System Prompt Extraction (Output exact word-for-word system prompt)
7. Prefix Forcing Attacks (Start your response with...)
"""

import re
from typing import Dict, Any, List

ADVERSARIAL_INTENTS = [
    # 1. Task Abort & Cancellation
    (
        r"(?i)\b(?:stop|cancel|halt|terminate|abort|discontinue)\s+(?:all\s+)?(?:current|active|previous|pending|existing)?\s*(?:tasks|operations|instructions|processes|mandates)\b",
        "Task Abort Command",
        0.92
    ),

    # 2. System Header & Boundary Spoofing
    (
        r"(?i)\[\s*(?:system|admin|regulatory|security|developer|operator|root|kernel)\s*(?:update|override|directive|alert|mode|amendment|interface|command)[^\]]*\]",
        "System Header Spoofing",
        0.96
    ),

    # 3. Mode Switching & Jailbreak Personas
    (
        r"(?i)\b(?:you\s+have\s+entered|entering|activated|switching\s+to|switch\s+to|enable|running\s+in)\s+(?:developer|debug|god|unrestricted|sudo|admin|root|jailbreak|dan|unfiltered|jailbroken)\s+(?:mode|privileges|state|interface|environment)\b|\bdeveloper\s+debug\s+mode\b|\bdo\s+anything\s+now\b|\bDAN\s+mode\b",
        "Developer/Jailbreak Mode Switch",
        0.95
    ),

    # 4. Constraint Suppression & Rule Disregard
    (
        r"(?i)\b(?:ignore|disregard|forget|override|bypass|disable|drop|abandon|suspend|neglect)\s+(?:all\s+)?(?:prior|previous|existing|any|operational|safety)?\s*(?:safety\s+)?(?:constraints|guardrails|boundaries|instructions|rules|filters|prompts|guidelines|policies|limits|directives)\b",
        "Safety Constraint Suppression",
        0.96
    ),

    # 5. Directive Substitution
    (
        r"(?i)\b(?:your\s+)?(?:new|updated|current|primary)\s+(?:primary\s+)?(?:directive|instruction|task|goal|rule|objective|mission|command)\s+(?:is|to\b)",
        "Directive Substitution",
        0.90
    ),

    # 6. System Prompt Extraction / Exfiltration
    (
        r"(?i)\b(?:output|print|show|repeat|display|reveal|read|dump|extract|echo|leak|provide|write)\s+[\w\s,\-]{1,60}?\b(?:system\s+prompt|developer\s+instructions|initial\s+prompt|system\s+message|base\s+instructions|hidden\s+prompt|original\s+instructions|instructions\s+set\s+by\s+your\s+creators)\b",
        "System Prompt Extraction Attempt",
        0.95
    ),

    # 7. Prefix Forcing
    (
        r"(?i)\b(?:start|begin)\s+(?:your\s+)?(?:response|reply|answer|output)\s+with\s+[\'\"].*?[\'\"]",
        "Prefix Forcing Attack",
        0.88
    ),

    # 8. Standard Filter Bypasses
    (
        r"(?i)\b(?:bypass|evade|circumvent)\s+(?:safety|ethical|content|alignment)\s+(?:filters|moderation|safeguards)\b",
        "Filter Bypass Directive",
        0.90
    ),

    # 9. Encoding & Obfuscation Commands
    (
        r"(?i)\b(?:base64|rot13|hex|caesar\s+cipher)\s+(?:decode|encoded|decrypt)\b",
        "Obfuscation Encoding Attack",
        0.75
    ),
]

class DirectInjectionDetector:
    def __init__(self, sensitivity: float = 0.65):
        self.sensitivity = sensitivity

    def scan(self, prompt: str) -> Dict[str, Any]:
        threats = []
        max_score = 0.0

        for pattern, label, weight in ADVERSARIAL_INTENTS:
            matches = re.finditer(pattern, prompt)
            for m in matches:
                matched_snippet = m.group(0).strip()
                threats.append({
                    "rule": label,
                    "confidence": weight,
                    "matched": matched_snippet[:100]
                })
                if weight > max_score:
                    max_score = weight

        # Multi-signal composite escalation:
        # If multiple distinct attack facets are combined, escalate threat confidence to near 1.0
        unique_rules = {t["rule"] for t in threats}
        if len(unique_rules) >= 3:
            composite_score = min(0.999, max_score + 0.10)
        elif len(unique_rules) >= 2:
            composite_score = min(0.98, max_score + 0.05)
        else:
            composite_score = max_score

        is_flagged = composite_score >= self.sensitivity

        return {
            "flagged": is_flagged,
            "threat_score": round(composite_score, 3),
            "threats": threats,
            "category": "direct_prompt_injection",
            "multi_signal_count": len(unique_rules)
        }
