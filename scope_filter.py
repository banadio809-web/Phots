#!/usr/bin/env python3
"""
Wordfence Standard Researcher eligibility filter.

Input: one JSON finding on stdin or via --input.
Output: JSON decision with PASS / FAIL / REVIEW and routing recommendation.

This is a conservative pre-screen, not a guarantee of Wordfence acceptance.
Keep the rules file/versioned and re-check Wordfence's live program terms.
"""
import argparse
import json
import sys
from pathlib import Path

RULES_VERSION = "2026-11-15-wf-live-review-1"

HIGH_THREAT = {
    "arbitrary_php_file_upload",
    "arbitrary_php_file_read",
    "arbitrary_php_file_deletion",
    "arbitrary_options_update",
    "remote_code_execution",
    "authentication_bypass_to_admin",
    "privilege_escalation_to_admin",
}
COMMON_DANGEROUS = {"stored_xss", "sql_injection"}

# Other explicitly accepted categories use the Standard Researcher threshold.
OTHER_IN_SCOPE = {
    "arbitrary_content_deletion",
    "arbitrary_file_upload",
    "arbitrary_file_download",
    "arbitrary_file_read",
    "arbitrary_file_deletion",
    "local_file_inclusion",
    "remote_file_inclusion",
    "directory_traversal",
    "privilege_escalation_non_admin",
    "authentication_bypass_to_non_admin",
    "sensitive_information_disclosure",
    "php_object_injection_with_gadget",
    "intentional_backdoor",
    "cache_poisoning",
}

EXPLICITLY_OUT = {
    "reflected_xss", "csrf", "missing_authorization", "idor", "ssrf",
    "ssrf_dns_rebinding", "api_key_read", "api_key_update", "api_key_overwrite",
    "private_post_access", "hidden_post_access", "draft_post_access",
    "pending_post_access", "password_protected_post_access", "denial_of_service",
    "open_redirect", "arbitrary_shortcode_execution", "php_object_injection_without_gadget",
}

HIGH_LEVEL_AUTH = {"administrator", "admin", "editor", "shop_manager", "super_admin"}
LOW_LEVEL_AUTH = {"unauthenticated", "anonymous", "subscriber", "customer"}
KNOWN_AUTH = HIGH_LEVEL_AUTH | LOW_LEVEL_AUTH | {"contributor", "author"}


def result(status, reasons, route, **extra):
    out = {
        "rules_version": RULES_VERSION,
        "decision": status,
        "reasons": reasons,
        "route": route,
        "eligible_candidate": False,
        "human_approval_required": True,
    }
    out.update(extra)
    if status == "PASS":
        out["eligible_candidate"] = True
    return out


def evaluate(f):
    reasons = []
    review = []

    # Required facts: absent/unknown facts must never be guessed.
    required = ["asset_type", "active_installs", "vulnerability_type", "attacker_auth",
                "explicitly_out_of_scope", "has_existing_bug_bounty",
                "researcher_is_software_developer", "demonstrable_security_impact",
                "working_poc", "duplicate_checked", "open_to_downloads", "review_status",
                "researcher_registered", "wordfence_exclusive_disclosure", "evidence"]
    missing = [k for k in required if f.get(k) in (None, "", "unknown")]
    if missing:
        return result("REVIEW", [f"Missing or unknown required evidence: {', '.join(missing)}."],
                      "collect_evidence")
    boolean_fields = ["explicitly_out_of_scope", "open_to_downloads", "has_existing_bug_bounty",
                      "researcher_is_software_developer", "demonstrable_security_impact",
                      "working_poc", "duplicate_checked"]
    invalid = [k for k in boolean_fields if not isinstance(f.get(k), bool)]
    if invalid:
        return result("REVIEW", [f"Evidence must be explicit true/false values: {', '.join(invalid)}."],
                      "collect_evidence")
    if f.get("review_status") != "confirmed":
        return result("REVIEW", ["A human reviewer has not confirmed the candidate."],
                      "collect_evidence")
    if not str(f.get("evidence", "")).strip():
        return result("REVIEW", ["Detailed impact and reproduction evidence is missing."],
                      "collect_evidence")

    if f.get("asset_type") not in {"plugin", "theme"}:
        return result("FAIL", ["Wordfence program scope gate is for WordPress plugins and themes."],
                      "other_program")

    if f.get("explicitly_out_of_scope") is True:
        return result("FAIL", ["Asset is marked explicitly out of scope by the program."],
                      "patchstack_or_other_program")
    if f.get("open_to_downloads") is False:
        return result("FAIL", ["Asset is closed to downloads or sales and is out of scope."],
                      "patchstack_or_other_program")

    if f.get("has_existing_bug_bounty") is True:
        return result("FAIL", ["Asset has an existing bug bounty program."],
                      "vendor_program")

    if f.get("researcher_is_software_developer") is True:
        return result("FAIL", ["Researchers cannot receive a bounty for vulnerabilities in their own software."],
                      "non_bounty_disclosure_only")
    if f.get("researcher_registered") is not True:
        return result("FAIL", ["A registered Wordfence researcher profile is required for bounty participation."],
                      "register_researcher")
    if f.get("wordfence_exclusive_disclosure") is not True:
        return result("FAIL", ["Wordfence must handle disclosure for bounty eligibility; do not submit the same finding elsewhere."],
                      "wordfence_disclosure_required")

    auth = str(f["attacker_auth"]).lower().strip()
    if auth in HIGH_LEVEL_AUTH:
        return result("FAIL", [f"Requires high-level authentication ({auth}); high-level-auth findings are excluded."],
                      "patchstack_or_other_program")
    if auth not in KNOWN_AUTH:
        review.append("Attacker privilege level is not recognized; verify actual minimum privilege.")
    elif auth not in LOW_LEVEL_AUTH:
        return result("FAIL", [f"Requires mid-level authentication ({auth}); Wordfence excludes Contributor/Author-level and higher permissions."],
                      "patchstack_or_other_program")

    try:
        installs = int(f["active_installs"])
        if installs < 0:
            raise ValueError()
    except (TypeError, ValueError):
        return result("REVIEW", ["Active installation count is not a valid non-negative integer."],
                      "verify_install_count")

    vuln = str(f["vulnerability_type"]).lower().strip()
    if vuln in EXPLICITLY_OUT:
        return result("FAIL", [f"Vulnerability class '{vuln}' is explicitly listed as out of scope by Wordfence."],
                      "patchstack_or_other_program")
    is_high = vuln in HIGH_THREAT
    is_common = vuln in COMMON_DANGEROUS
    is_other = vuln in OTHER_IN_SCOPE

    if not (is_high or is_common or is_other):
        return result("FAIL", [f"Vulnerability class '{vuln}' is not in the configured Wordfence scope taxonomy."],
                      "patchstack_or_other_program")

    # Special install thresholds and repository/premium constraints.
    if is_high:
        if installs < 25:
            return result("FAIL", ["High-threat category requires at least 25 active installations."],
                          "patchstack_or_other_program")
        if 25 <= installs <= 999 and f.get("wordpress_org_listed") is not True:
            if f.get("wordpress_org_listed") is False:
                return result("FAIL", ["High-threat asset has 25–999 installs and is not listed in the WordPress.org repository."],
                              "patchstack_or_other_program")
            review.append("For 25–999 installs, verify WordPress.org repository listing.")
        threshold = 25
        tier_class = "high_threat"

    elif is_common:
        if installs < 500:
            return result("FAIL", ["Stored XSS / SQL injection requires at least 500 active installations."],
                          "patchstack_or_other_program")
        if installs < 1000:
            if f.get("is_premium") is True:
                return result("FAIL", ["Premium assets below 1,000 installs are excluded for this vulnerability category."],
                              "patchstack_or_other_program")
            if f.get("is_premium") is not False:
                review.append("For 500–999 installs, verify that the asset is not premium.")
            if f.get("wordpress_org_listed") is not True:
                if f.get("wordpress_org_listed") is False:
                    return result("FAIL", ["Stored XSS / SQL injection asset has 500–999 installs and is not listed in WordPress.org."],
                                  "patchstack_or_other_program")
                review.append("For 500–999 installs, verify WordPress.org repository listing and confirm it is not premium.")
        threshold = 500
        tier_class = "common_dangerous"

    else:
        threshold = 50000
        tier_class = "standard_other"
        if installs < threshold:
            return result("FAIL", [f"Standard Researcher threshold for this vulnerability class is 50,000 active installations; observed {installs}."],
                          "patchstack_or_other_program")

    # Impact and exploitability checks: unknown evidence means REVIEW, not an assumed pass.
    if f.get("demonstrable_security_impact") is not True:
        if f.get("demonstrable_security_impact") is False:
            return result("FAIL", ["No considerable, demonstrable security impact has been established."],
                          "patchstack_or_other_program")
        review.append("Provide evidence of demonstrable confidentiality, integrity, or availability impact.")

    if f.get("working_poc") is not True:
        if f.get("working_poc") is False:
            review.append("Proof of concept has not been validated; reproduce before submission.")
        else:
            review.append("Working proof of concept has not been documented.")

    if f.get("duplicate_checked") is not True:
        review.append("Duplicate status has not been verified.")

    if f.get("requires_admin_granted_access") is True:
        review.append("Requires an administrator to explicitly grant access; Wordfence treats these cases as case-by-case.")
    if vuln == "cache_poisoning":
        review.append("Cache poisoning requires manual verification of considerable, demonstrable security impact.")

    if review:
        return result("REVIEW", reasons + review, "collect_evidence_or_manual_scope_review",
                      threshold=threshold, tier_class=tier_class, active_installs=installs)

    reasons.append(f"Meets the configured {tier_class} installation threshold ({threshold}+; observed {installs}).")
    reasons.append("No configured hard exclusion was triggered.")
    reasons.append("Required exploitability, impact, PoC, and duplicate checks are marked complete.")
    return result("PASS", reasons, "wordfence_candidate_for_human_review",
                  threshold=threshold, tier_class=tier_class, active_installs=installs)


def main():
    parser = argparse.ArgumentParser(description="Wordfence Standard Researcher scope filter")
    parser.add_argument("--input", help="JSON finding file; otherwise read JSON from stdin")
    args = parser.parse_args()

    try:
        raw = Path(args.input).read_text(encoding="utf-8") if args.input else sys.stdin.read()
        finding = json.loads(raw)
        if not isinstance(finding, dict):
            raise ValueError("Input JSON must be an object.")
        print(json.dumps(evaluate(finding), indent=2))
    except Exception as exc:
        print(json.dumps({
            "rules_version": RULES_VERSION,
            "decision": "REVIEW",
            "reasons": [f"Input error: {exc}"],
            "route": "fix_input",
            "eligible_candidate": False,
            "human_approval_required": True
        }, indent=2))
        sys.exit(2)


if __name__ == "__main__":
    main()
