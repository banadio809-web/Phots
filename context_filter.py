# Neutralizing-context signatures (PHP)
import json
from pathlib import Path

ACCESS_CONTROL = [
    r"\bcurrent_user_can\s*\(",
    r"\bcurrent_user_can_for_blog\s*\(",
    r"\buser_can\s*\(",
    r"\bcheck_admin_referer\s*\(",
    r"\bcheck_ajax_referer\s*\(",
    r"\bverify_ajax_request\s*\(",
    r"\bwp_nonce_field\s*\(",
    r"\bwp_verify_nonce\s*\(",
    r"\badmin\s*\(",
]

SANITIZATION = [
    r"\bsanitize_text_field\s*\(",
    r"\bsanitize_key\s*\(",
    r"\bsanitize_email\s*\(",
    r"\bsanitize_url\s*\(",
    r"\bsanitize_file_name\s*\(",
    r"\bsanitize_title\s*\(",
    r"\bsanitize_hex_color\s*\(",
    r"\bsanitize_html_class\s*\(",
    r"\bintval\s*\(",
    r"\babsint\s*\(",
    r"\bfilter_var\s*\(",
    r"\bwp_kses\s*\(",
    r"\bwp_kses_post\s*\(",
    r"\bwp_kses_data\s*\(",
    r"\bvalidate_file\s*\(",
]

OUTPUT_ENCODING = [
    r"\besc_html\s*\(",
    r"\besc_attr\s*\(",
    r"\besc_url\s*\(",
    r"\besc_url_raw\s*\(",
    r"\besc_textarea\s*\(",
    r"\besc_js\s*\(",
    r"\bwp_json_encode\s*\(",
    r"\bwp_strip_all_tags\s*\(",
    r"\bhtmlspecialchars\s*\(",
    r"\bhtmlentities\s*\(",
]

ALLOWLIST = [
    r"\bisset\s*\(",
    r"\bin_array\s*\(",
    r"\barray_key_exists\s*\(",
    r"\bswitch\s*\(",
    r"\brealpath\s*\(",
]

def verdict_for(flags: ContextFlags, hint: str) -> tuple[str, list[str]]:
    """Determine the verdict based on accumulated context flags."""
    reasons = list(flags.suppression_reasons)
    
    # If inside a comment, suppress
    if flags.is_in_comment:
        return "suppressed", reasons + ["match inside comment/docblock"]
    
    # If vendor code without access control, needs_review
    if flags.is_vendor_code and not flags.has_access_control:
        return "needs_review", reasons + ["vendor code without access control"]
    
    # SQL injection / RCE behind access control + sanitization (higher risk,
    # so require both before suppressing).
    if hint in {"sql_injection", "remote_code_execution", "php_object_injection_with_gadget"}:
        if (flags.has_capability or flags.has_access_control) and flags.has_sanitization:
            reasons.append("sink behind capability + sanitization")
            return "needs_review", reasons
        reasons.append("no neutralizing access-control/sanitization confirmed")
        return "needs_review", reasons
    
    # Generic: strong neutralizing context (3+ categories) -> suppressed.
    strong_categories = sum([
        bool(flags.has_access_control),
        bool(flags.has_sanitization),
        bool(flags.has_output_encoding),
        bool(flags.has_allowlist),
        bool(flags.has_type_validation),
        bool(flags.has_guard_clause),
    ])
    if strong_categories >= 3:
        reasons.append(f"{strong_categories} neutralizing context categories detected")
        return "suppressed", reasons
    
    if flags.neutralizing_score >= 5:
        reasons.append("moderate+ neutralizing context detected")
        return "needs_review", reasons
    
    # If has strong access control + sanitization, needs_review for high-risk
    if hint in {"sql_injection", "remote_code_execution", "php_object_injection_with_gadget"}:
        if flags.has_access_control and flags.has_sanitization:
            reasons.append("access control + sanitization present but not confirmed sufficient")
            return "needs_review", reasons
    
    return "needs_review", reasons
def apply_context_filter(findings: list[dict], root_path: Path) -> tuple[list[dict], list[dict]]:
    """Apply context-aware suppression to a list of findings.
    
    Returns ``(suppressed, kept)`` lists. Suppressed findings receive a
    ``context_verdict`` of ``"suppressed"`` plus ``suppression_reasons``;
    kept findings receive ``context_verdict`` of ``"needs_review"`` or
    ``"confirmed_signal"``.
    
    Files are re-read from ``root_path`` / ``finding[\"file\"]`` to inspect the
    full source around each match.
    """
    suppressed: list[dict] = []
    kept: list[dict] = []
    source_cache: dict[str, str] = {}
    
    for finding in findings:
        file_path = str(finding.get("file", ""))
        root = Path(root_path)
        candidate = root / file_path
        if not candidate.is_absolute():
            candidate = root / file_path
        if str(candidate) not in source_cache:
            try:
                source_cache[str(candidate)] = _read_file(candidate)
            except (OSError, UnicodeDecodeError):
                source_cache[str(candidate)] = ""
        source_text = source_cache[str(candidate)]
        
        flags = analyze_context(finding, source_text)
        verdict, reasons = verdict_for(flags, str(finding.get("class_hint") or ""))
        
        finding = dict(finding)
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
        
        if verdict == "suppressed":
            suppressed.append(finding)
        else:
            kept.append(finding)
    
    return suppressed, kept


def _read_file(candidate: Path) -> str:
    """Read file content with proper encoding handling."""
    try:
        return candidate.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return ""


def load_reviewed_clean(path: Path) -> set[str]:
    """Load the set of signal_ids previously reviewed as clean (false positives)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return set(data.get("reviewed_clean", []))
    except (OSError, ValueError):
        return set()


def save_reviewed_clean(path: Path, signal_ids: set[str]) -> None:
    """Persist the set of signal_ids reviewed as clean."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"reviewed_clean": sorted(signal_ids)}, indent=2),
        encoding="utf-8",
    )