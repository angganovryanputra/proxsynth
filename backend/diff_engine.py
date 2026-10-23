"""
Proxsynth - Semantic Structural Diffing & Noise Reduction Engine
Normalizes dynamic tokens, timestamps, nonces, and volatile session parameters to deliver
deterministic differential analysis, eliminating token bloat and detecting Soft-403 / Soft-404 heuristics.
"""

import re
import difflib
from typing import Dict, Any, List, Optional, Tuple

# Dynamic noise regex patterns
ISO_TIMESTAMP_PATTERN = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
EPOCH_TIMESTAMP_PATTERN = re.compile(r"\b1[5-9]\d{8}(?:\d{3})?\b")
UUID_PATTERN = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
HEX_HASH_PATTERN = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
CSRF_TOKEN_PATTERN = re.compile(
    r"""(?i)(?:csrf[_-]?token|_csrf|authenticity[_-]?token|csrfmiddlewaretoken|anti[_-]?forgery|nonce)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-\.\/+=]{10,})["']"""
)

# Soft Error heuristic patterns
SOFT_403_PATTERNS = [
    re.compile(r"(?:access\s+denied|permission\s+denied|unauthorized|insufficient\s+privileges|access\s+forbidden|not\s+authorized|login\s+required|please\s+sign\s+in|authentication\s+required|session\s+expired)", re.IGNORECASE),
    re.compile(r"""(?:["']error["']\s*:\s*["'](?:unauthorized|forbidden|access_denied)["'])""", re.IGNORECASE)
]

SOFT_404_PATTERNS = [
    re.compile(r"(?:page\s+not\s+found|item\s+not\s+found|resource\s+not\s+found|does\s+not\s+exist|could\s+not\s+find|no\s+records\s+found|user\s+not\s+found|object\s+not\s+found|404\s+not\s+found|file\s+not\s+found)", re.IGNORECASE),
    re.compile(r"""(?:["']error["']\s*:\s*["'](?:not_found|not\s+found)["'])""", re.IGNORECASE)
]


def clean_dynamic_tokens(text: str) -> str:
    """
    Strips volatile dynamic noise from HTTP response bodies.
    Normalizes timestamps, UUIDs, hex hashes, and CSRF tokens to fixed placeholders.
    """
    if not text:
        return ""

    normalized = ISO_TIMESTAMP_PATTERN.sub("<TIMESTAMP>", text)
    normalized = EPOCH_TIMESTAMP_PATTERN.sub("<EPOCH>", normalized)
    normalized = UUID_PATTERN.sub("<UUID>", normalized)
    normalized = HEX_HASH_PATTERN.sub("<HEX_HASH>", normalized)
    normalized = CSRF_TOKEN_PATTERN.sub(r'csrf_token="<CSRF>"', normalized)
    return normalized


def detect_soft_errors(status_code: int, body_text: str) -> Dict[str, Any]:
    """
    Heuristically checks if a nominally successful response (e.g. HTTP 200/201)
    is actually a Soft 403 (Unauthorized / Forbidden) or Soft 404 (Resource Not Found).
    """
    is_nominal_success = 200 <= status_code < 300
    soft_403_matches = []
    soft_404_matches = []

    if is_nominal_success and body_text:
        snippet = body_text[:10000]  # Examine first 10KB
        for pat in SOFT_403_PATTERNS:
            found = pat.findall(snippet)
            if found:
                soft_403_matches.extend(found if isinstance(found[0], str) else [str(f) for f in found])

        for pat in SOFT_404_PATTERNS:
            found = pat.findall(snippet)
            if found:
                soft_404_matches.extend(found if isinstance(found[0], str) else [str(f) for f in found])

    return {
        "is_soft_403": bool(soft_403_matches),
        "is_soft_404": bool(soft_404_matches),
        "soft_403_indicators": list(set(soft_403_matches))[:5],
        "soft_404_indicators": list(set(soft_404_matches))[:5]
    }


def compute_semantic_diff(
    response_a: Dict[str, Any],
    response_b: Dict[str, Any],
    max_diff_lines: int = 50
) -> Dict[str, Any]:
    """
    Performs comprehensive structural diffing between two HTTP response dictionaries.
    Inputs are expected to have:
      - status_code: int
      - body: str
      - headers: Optional[Dict[str, str]]
    """
    status_a = int(response_a.get("status_code", 0))
    status_b = int(response_b.get("status_code", 0))
    raw_body_a = str(response_a.get("body", "") or "")
    raw_body_b = str(response_b.get("body", "") or "")

    headers_a = response_a.get("headers") or {}
    headers_b = response_b.get("headers") or {}

    # 1. Clean dynamic noise
    norm_body_a = clean_dynamic_tokens(raw_body_a)
    norm_body_b = clean_dynamic_tokens(raw_body_b)

    # 2. Compute similarity ratios with bounded sample size to prevent quadratic algorithmic exhaustion
    sample_a = raw_body_a[:150000]
    sample_b = raw_body_b[:150000]
    sample_norm_a = norm_body_a[:150000]
    sample_norm_b = norm_body_b[:150000]

    raw_matcher = difflib.SequenceMatcher(None, sample_a, sample_b)
    raw_similarity = round(raw_matcher.ratio(), 4)

    norm_matcher = difflib.SequenceMatcher(None, sample_norm_a, sample_norm_b)
    normalized_similarity = round(norm_matcher.ratio(), 4)

    # 3. Soft Error Analysis
    soft_a = detect_soft_errors(status_a, raw_body_a)
    soft_b = detect_soft_errors(status_b, raw_body_b)

    # 4. Extract meaningful line diffs
    lines_a = norm_body_a.splitlines()
    lines_b = norm_body_b.splitlines()

    unified = list(difflib.unified_diff(
        lines_a, lines_b,
        fromfile="Response_A",
        tofile="Response_B",
        lineterm="",
        n=2
    ))

    significant_diffs: List[str] = []
    for line in unified:
        # Keep added/removed lines, omit header metadata
        if (line.startswith("+") and not line.startswith("+++")) or (line.startswith("-") and not line.startswith("---")):
            significant_diffs.append(line)
            if len(significant_diffs) >= max_diff_lines:
                significant_diffs.append(f"... [Truncated. Remaining diff lines omitted]")
                break

    # 5. Header deltas
    header_diffs = []
    all_header_keys = set([k.lower() for k in headers_a.keys()]).union(set([k.lower() for k in headers_b.keys()]))
    for hk in sorted(all_header_keys):
        # Ignore volatile headers like Date or Content-Length
        if hk in ("date", "content-length", "set-cookie", "x-request-id", "x-amzn-trace-id"):
            continue
        val_a = headers_a.get(hk) or headers_a.get(hk.title()) or headers_a.get(hk.upper())
        val_b = headers_b.get(hk) or headers_b.get(hk.title()) or headers_b.get(hk.upper())
        if val_a != val_b:
            header_diffs.append({
                "header": hk,
                "val_a": val_a,
                "val_b": val_b
            })

    # 6. Assess substantive difference
    is_substantive = (
        status_a != status_b
        or normalized_similarity < 0.95
        or soft_a["is_soft_403"] != soft_b["is_soft_403"]
        or soft_a["is_soft_404"] != soft_b["is_soft_404"]
    )

    return {
        "status_a": status_a,
        "status_b": status_b,
        "status_changed": status_a != status_b,
        "raw_length_a": len(raw_body_a),
        "raw_length_b": len(raw_body_b),
        "raw_length_delta": len(raw_body_b) - len(raw_body_a),
        "normalized_length_a": len(norm_body_a),
        "normalized_length_b": len(norm_body_b),
        "raw_similarity_ratio": raw_similarity,
        "normalized_similarity_ratio": normalized_similarity,
        "is_substantively_different": is_substantive,
        "soft_error_a": soft_a,
        "soft_error_b": soft_b,
        "header_differences": header_diffs[:15],
        "structural_diff_lines": significant_diffs,
        "summary": (
            f"Comparison Result: {'SUBSTANTIVE DIFFERENCE DETECTED' if is_substantive else 'IDENTICAL BEHAVIOR (NOISE-FILTERED)'}. "
            f"Normalized Similarity: {normalized_similarity * 100:.1f}%. "
            f"Status: {status_a} vs {status_b}."
        )
    }
