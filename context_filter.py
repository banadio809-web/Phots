"""Conservative source-context annotations for scanner findings.

Context signals help prioritize manual review; they do not prove that a
finding is safe. Only a finding located inside a source comment is suppressed.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ACCESS_CONTROL = re.compile(
    r"\b(?:current_user_can(?:_for_blog)?|user_can|is_admin|is_user_logged_in)\s*\(|"
    r"\b(?:check_admin_referer|check_ajax_referer|wp_verify_nonce|verify_ajax_request)\s*\("
    r"|\bpermission_callback\b|\bmanage_options\b",
    re.IGNORECASE,
)
SANITIZATION = re.compile(
    r"\b(?:sanitize_[a-z0-9_]+|absint|intval|filter_var|wp_kses(?:_post|_data)?|"
    r"esc_html|esc_attr|esc_url|esc_textarea|esc_js|htmlspecialchars|htmlentities)\s*\(|"
    r"\b(?:basename|realpath|wp_normalize_path)\s*\(",
    re.IGNORECASE,
)
OUTPUT_ENCODING = re.compile(
    r"\b(?:esc_html|esc_attr|esc_url|esc_textarea|esc_js|wp_kses(?:_post|_data)?|"
    r"wp_json_encode|htmlspecialchars|htmlentities)\s*\(",
    re.IGNORECASE,
)
ALLOWLIST = re.compile(
    r"\b(?:isset|in_array|array_key_exists|switch|realpath|basename)\s*\(|"
    r"\b(?:allowed|whitelist|allowlist|valid_values|supported_types)\b",
    re.IGNORECASE,
)
TYPE_VALIDATION = re.compile(
    r"\b(?:is_int|is_integer|is_numeric|is_array|is_string|is_bool|ctype_digit|"
    r"absint|intval|filter_var|sanitize_key)\s*\(|\(int\)",
    re.IGNORECASE,
)
GUARD_CLAUSE = re.compile(
    r"\b(?:wp_die|wp_send_json_error|wp_die|die|exit|return\s+(?:false|null))\b|"
    r"\bif\s*\([^)]*(?:===?\s*false|empty\s*\(|!\s*\$)",
    re.IGNORECASE,
)
REST_VALIDATION = re.compile(
    r"\b(?:register_rest_route|validate_callback|sanitize_callback|WP_REST_Request|get_param)\b",
    re.IGNORECASE,
)
COMMENT_START = re.compile(r"^\s*(?://|#|/\*|\*|\*/|<!--)")


@dataclass
class ContextFlags:
    has_access_control: bool = False
    has_capability: bool = False
    has_sanitization: bool = False
    has_output_encoding: bool = False
    has_allowlist: bool = False
    has_type_validation: bool = False
    has_guard_clause: bool = False
    has_data_validation: bool = False
    has_string_context: bool = False
    has_rest_validation: bool = False
    is_vendor_code: bool = False
    is_in_comment: bool = False
    neutralizing_score: int = 0
    suppression_reasons: list[str] = field(default_factory=list)


def _finding_line(finding: dict[str, Any]) -> int:
    try:
        return max(1, int(finding.get("line", 1)))
    except (TypeError, ValueError):
        return 1


def analyze_context(finding: dict[str, Any], source_text: str) -> ContextFlags:
    """Collect nearby context indicators without treating them as proof of safety."""
    flags = ContextFlags()
    lines = source_text.splitlines()
    line_number = _finding_line(finding)
    index = min(line_number - 1, max(0, len(lines) - 1))
    evidence = "\n".join(lines[max(0, index - 5):min(len(lines), index + 6)])
    target_line = lines[index] if lines else ""

    flags.has_access_control = bool(ACCESS_CONTROL.search(evidence))
    flags.has_capability = bool(re.search(r"\b(?:current_user_can|user_can)\s*\(", evidence, re.I))
    flags.has_sanitization = bool(SANITIZATION.search(evidence))
    flags.has_output_encoding = bool(OUTPUT_ENCODING.search(evidence))
    flags.has_allowlist = bool(ALLOWLIST.search(evidence))
    flags.has_type_validation = bool(TYPE_VALIDATION.search(evidence))
    flags.has_guard_clause = bool(GUARD_CLAUSE.search(evidence))
    flags.has_data_validation = bool(re.search(r"\b(?:validate|validation|is_valid|check_\w+)\b", evidence, re.I))
    flags.has_string_context = any(marker in evidence for marker in ("'", '"', ".", "sprintf", "printf"))
    flags.has_rest_validation = bool(REST_VALIDATION.search(evidence))
    normalized_path = str(finding.get("file", "")).replace("\\", "/").lower()
    flags.is_vendor_code = any(part in {"vendor", "vendors", "third-party", "third_party"}
                               for part in normalized_path.split("/"))
    flags.is_in_comment = bool(COMMENT_START.match(target_line))
    flags.neutralizing_score = sum((
        flags.has_access_control,
        flags.has_sanitization,
        flags.has_output_encoding,
        flags.has_allowlist,
        flags.has_type_validation,
        flags.has_guard_clause,
    ))
    if flags.has_capability:
        flags.suppression_reasons.append("nearby capability check detected; verify it guards this sink")
    elif flags.has_access_control:
        flags.suppression_reasons.append("nearby access or nonce check detected; verify its scope")
    if flags.has_sanitization:
        flags.suppression_reasons.append("nearby sanitization detected; verify it applies to the tainted value")
    if flags.has_output_encoding:
        flags.suppression_reasons.append("nearby output encoding detected; verify correct context and value")
    if flags.is_vendor_code:
        flags.suppression_reasons.append("finding is in a vendor/third-party path")
    if flags.is_in_comment:
        flags.suppression_reasons.append("finding line is a source comment")
    return flags


def verdict_for(flags: ContextFlags, hint: str) -> tuple[str, list[str]]:
    """Return a conservative disposition; nearby guards never auto-close a lead."""
    reasons = list(flags.suppression_reasons)
    if flags.is_in_comment:
        return "suppressed", reasons
    if flags.is_vendor_code:
        reasons.append("third-party code still requires validation against the shipped version")
    if hint in {"sql_injection", "remote_code_execution", "php_object_injection_with_gadget"}:
        if flags.has_access_control or flags.has_sanitization:
            reasons.append("high-risk class remains open despite nearby controls")
        else:
            reasons.append("no nearby access-control or sanitization evidence found")
        return "needs_review", reasons
    if flags.neutralizing_score:
        reasons.append(f"{flags.neutralizing_score} nearby context indicators; source-to-sink flow is unverified")
    else:
        reasons.append("no nearby neutralizing context identified")
    return "needs_review", reasons


def _safe_source_path(root_path: Path, file_path: str) -> Path | None:
    root = Path(root_path).resolve()
    candidate = (root / file_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def apply_context_filter(findings: list[dict], root_path: Path) -> tuple[list[dict], list[dict]]:
    """Return ``(suppressed, kept)`` with context details attached to each copy."""
    suppressed: list[dict] = []
    kept: list[dict] = []
    source_cache: dict[Path, str] = {}
    root = Path(root_path).resolve()

    for original in findings:
        finding = dict(original)
        candidate = _safe_source_path(root, str(finding.get("file", "")))
        if candidate is None:
            source_text = ""
            read_reason = "finding path is outside the scanned source root; no source was read"
        else:
            if candidate not in source_cache:
                source_cache[candidate] = _read_file(candidate)
            source_text = source_cache[candidate]
            read_reason = "source file unavailable; context could not be verified" if not source_text else None

        flags = analyze_context(finding, source_text)
        verdict, reasons = verdict_for(flags, str(finding.get("class_hint") or ""))
        if read_reason:
            verdict = "needs_review"
            reasons.append(read_reason)
        finding["context_verdict"] = verdict
        finding["suppression_reasons"] = reasons
        finding["context_flags"] = {
            "access_control": flags.has_access_control,
            "sanitization": flags.has_sanitization,
            "output_encoding": flags.has_output_encoding,
            "allowlist": flags.has_allowlist,
            "type_validation": flags.has_type_validation,
            "guard_clause": flags.has_guard_clause,
            "data_validation": flags.has_data_validation,
            "string_context": flags.has_string_context,
            "rest_validation": flags.has_rest_validation,
            "vendor": flags.is_vendor_code,
            "comment": flags.is_in_comment,
        }
        (suppressed if verdict == "suppressed" else kept).append(finding)

    return suppressed, kept


def _read_file(candidate: Path) -> str:
    try:
        return candidate.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def load_reviewed_clean(path: Path) -> set[str]:
    """Load reviewed IDs; invalid, malformed, or unexpected file shapes fail closed."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return set()
    values = data.get("reviewed_clean", []) if isinstance(data, dict) else []
    if not isinstance(values, list):
        return set()
    return {value for value in values if isinstance(value, str)}


def save_reviewed_clean(path: Path, signal_ids: set[str]) -> None:
    """Persist reviewed signal IDs as JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"reviewed_clean": sorted(signal_ids)}, indent=2), encoding="utf-8")
