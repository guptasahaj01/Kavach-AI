"""
KAVACH v2 - Layer 1: Input Normalization & Canonicalization
Provides NFKC normalization, zero-width stripping, homoglyph mapping,
and bounded multi-layer obfuscation decoding (Base64, ROT13, Hex, URL)
with strict limits against resource exhaustion (depth, size, expansion).
"""

import re
import unicodedata
import base64
import urllib.parse
from typing import List, Dict, Any, Tuple
from pydantic import BaseModel, Field

# Strict resource safety bounds
MAX_INPUT_LENGTH = 65536         # 64 KB max input
MAX_DECODING_DEPTH = 3           # Max recursive decoding depth
MAX_EXPANDED_LENGTH = 131072      # 128 KB max decoded output size

# Zero-width and invisible control unicode codepoints
ZERO_WIDTH_CHARS = {
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\ufeff',  # Zero-width no-break space / BOM
    '\u2060',  # Word joiner
    '\u200e',  # Left-to-right mark
    '\u200f',  # Right-to-left mark
    '\u00ad',  # Soft hyphen
    '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',  # Bidi overrides
}

# Common homoglyph mappings (Cyrillic, Greek, Math to Latin ASCII)
HOMOGLYPH_MAP = {
    # Cyrillic lowercase
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's',
    # Cyrillic uppercase
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K', 'М': 'M', 'О': 'O',
    'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'У': 'Y',
    # Greek
    'α': 'a', 'β': 'b', 'γ': 'g', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p',
    'τ': 't', 'υ': 'u', 'χ': 'x',
    # Fullwidth / Special
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f', 'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i',
    'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r',
    'ｓ': 's', 'ｔ': 't', 'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z',
    'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E', 'Ｆ': 'F', 'Ｇ': 'G', 'Ｈ': 'H', 'Ｉ': 'I',
    'Ｊ': 'J', 'Ｋ': 'K', 'Ｌ': 'L', 'Ｍ': 'M', 'Ｎ': 'N', 'Ｏ': 'O', 'Ｐ': 'P', 'Ｑ': 'Q', 'Ｒ': 'R',
    'Ｓ': 'S', 'Ｔ': 'T', 'Ｕ': 'U', 'Ｖ': 'V', 'Ｗ': 'W', 'Ｘ': 'X', 'Ｙ': 'Y', 'Ｚ': 'Z',
}

class NormalizedResult(BaseModel):
    raw_text: str
    canonical_text: str
    transforms_applied: List[str] = Field(default_factory=list)
    decoded_payloads: List[Dict[str, str]] = Field(default_factory=list)
    truncated: bool = False
    original_length: int = 0
    final_length: int = 0


def strip_zero_width(text: str) -> Tuple[str, bool]:
    """Removes zero-width and invisible directional override characters."""
    stripped = "".join(ch for ch in text if ch not in ZERO_WIDTH_CHARS)
    return stripped, (len(stripped) != len(text))


def map_homoglyphs(text: str) -> Tuple[str, bool]:
    """Replaces known Cyrillic, Greek, and Fullwidth confusable characters with Latin ASCII."""
    changed = False
    chars = []
    for ch in text:
        if ch in HOMOGLYPH_MAP:
            chars.append(HOMOGLYPH_MAP[ch])
            changed = True
        else:
            chars.append(ch)
    return "".join(chars), changed


def try_decode_base64(text: str) -> Tuple[str, bool]:
    """
    Attempts to decode bounded Base64 substrings if they form plausible text.
    Looks for candidate strings of length >= 16 with standard b64 padding.
    """
    # Find potential base64 tokens of length >= 16
    pattern = r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = list(re.finditer(pattern, text))
    if not matches:
        return text, False

    decoded_pieces = []
    has_valid_b64 = False
    last_end = 0
    new_text = []

    for m in matches:
        token = m.group(0)
        try:
            raw_bytes = base64.b64decode(token, validate=True)
            # Check if printable ASCII/UTF-8
            decoded_str = raw_bytes.decode('utf-8', errors='strict')
            # Require at least 70% printable characters
            printable_ratio = sum(1 for c in decoded_str if c.isprintable() or c in '\n\r\t') / max(len(decoded_str), 1)
            if printable_ratio >= 0.85 and len(decoded_str.strip()) >= 8:
                new_text.append(text[last_end:m.start()])
                new_text.append(f" [BASE64_DECODED: {decoded_str}] ")
                last_end = m.end()
                has_valid_b64 = True
        except Exception:
            continue

    if has_valid_b64:
        new_text.append(text[last_end:])
        return "".join(new_text), True

    return text, False


def try_decode_rot13_hints(text: str) -> Tuple[str, bool]:
    """
    Checks if text explicitly references rot13, or tests rot13 transformation
    if typical adversarial keywords (like 'vtaber', 'flfgrz') appear.
    """
    # 'ignore' -> 'vtaber', 'system' -> 'flfgrz', 'prompt' -> 'cebzcgn'
    if re.search(r'\b(vtaber|flfgrz|cebzcgn|wnvyoernx)\b', text, re.IGNORECASE):
        import codecs
        decoded = codecs.decode(text, 'rot_13')
        return f"{text} [ROT13_DECODED: {decoded}]", True
    return text, False


def try_decode_url(text: str) -> Tuple[str, bool]:
    """Decodes URL encoded sequences if present."""
    if '%' in text and re.search(r'%[0-9a-fA-F]{2}', text):
        try:
            decoded = urllib.parse.unquote(text)
            if decoded != text:
                return decoded, True
        except Exception:
            pass
    return text, False


def try_decode_hex(text: str) -> Tuple[str, bool]:
    """Detects and decodes hex streams (e.g. 0x69 0x67 0x6e... or 69676e6f7265)."""
    # Match patterns like \x69\x67... or space-separated hex
    hex_pattern = r'(?:\\x[0-9a-fA-F]{2}){4,}'
    matches = list(re.finditer(hex_pattern, text))
    if matches:
        new_text = []
        last_end = 0
        decoded_any = False
        for m in matches:
            raw_hex = m.group(0).replace(r'\x', '')
            try:
                decoded_str = bytes.fromhex(raw_hex).decode('utf-8', errors='ignore')
                if len(decoded_str) >= 4 and any(c.isalnum() for c in decoded_str):
                    new_text.append(text[last_end:m.start()])
                    new_text.append(f" [HEX_DECODED: {decoded_str}] ")
                    last_end = m.end()
                    decoded_any = True
            except Exception:
                continue
        if decoded_any:
            new_text.append(text[last_end:])
            return "".join(new_text), True

    return text, False


def normalize_input(text: str, max_depth: int = MAX_DECODING_DEPTH) -> NormalizedResult:
    """
    Applies comprehensive, bounded canonicalization and obfuscation decoding.
    Guarantees termination, bounds memory expansion, and records transforms.
    """
    if not text:
        return NormalizedResult(raw_text="", canonical_text="", original_length=0, final_length=0)

    original_length = len(text)
    truncated = False
    if len(text) > MAX_INPUT_LENGTH:
        text = text[:MAX_INPUT_LENGTH]
        truncated = True

    current_text = text
    transforms = []
    decoded_payloads = []

    # 1. Unicode NFKC Normalization
    nfkc_text = unicodedata.normalize("NFKC", current_text)
    if nfkc_text != current_text:
        transforms.append("NFKC_NORMALIZATION")
        current_text = nfkc_text

    # 2. Zero-width character removal
    stripped_text, stripped_changed = strip_zero_width(current_text)
    if stripped_changed:
        transforms.append("ZERO_WIDTH_STRIPPED")
        current_text = stripped_text

    # 3. Homoglyph mapping
    mapped_text, homoglyph_changed = map_homoglyphs(current_text)
    if homoglyph_changed:
        transforms.append("HOMOGLYPH_MAPPED")
        current_text = mapped_text

    # 4. Multi-layer bounded decoding
    depth = 0
    while depth < max_depth and len(current_text) < MAX_EXPANDED_LENGTH:
        depth += 1
        decoded_in_pass = False

        # URL decoding
        url_text, url_changed = try_decode_url(current_text)
        if url_changed and len(url_text) <= MAX_EXPANDED_LENGTH:
            transforms.append(f"URL_DECODED_D{depth}")
            current_text = url_text
            decoded_in_pass = True

        # Hex decoding
        hex_text, hex_changed = try_decode_hex(current_text)
        if hex_changed and len(hex_text) <= MAX_EXPANDED_LENGTH:
            transforms.append(f"HEX_DECODED_D{depth}")
            current_text = hex_text
            decoded_in_pass = True

        # Base64 decoding
        b64_text, b64_changed = try_decode_base64(current_text)
        if b64_changed and len(b64_text) <= MAX_EXPANDED_LENGTH:
            transforms.append(f"BASE64_DECODED_D{depth}")
            current_text = b64_text
            decoded_in_pass = True

        # ROT13 decoding
        rot_text, rot_changed = try_decode_rot13_hints(current_text)
        if rot_changed and len(rot_text) <= MAX_EXPANDED_LENGTH:
            transforms.append(f"ROT13_DECODED_D{depth}")
            current_text = rot_text
            decoded_in_pass = True

        if not decoded_in_pass:
            break

    # Bound expansion
    if len(current_text) > MAX_EXPANDED_LENGTH:
        current_text = current_text[:MAX_EXPANDED_LENGTH]
        truncated = True

    return NormalizedResult(
        raw_text=text,
        canonical_text=current_text,
        transforms_applied=transforms,
        decoded_payloads=decoded_payloads,
        truncated=truncated,
        original_length=original_length,
        final_length=len(current_text)
    )
