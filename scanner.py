#!/usr/bin/env python3
"""Offline WordPress.org plugin source triage. Signals are not confirmed vulnerabilities."""

from __future__ import annotations

import argparse
import bisect
from collections import deque
import concurrent.futures
import ctypes
import getpass
import os
import hashlib
import heapq
import html
import json
import re
import queue as queue_module
import shutil
import site
import sqlite3
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from scope_filter import (COMMON_DANGEROUS, HIGH_THREAT, OTHER_IN_SCOPE,
                          evaluate as evaluate_scope)
from ai_triage import AIConfig, AIMemory, AIReviewer, load_env_file, save_ai_settings
from supabase_store import SupabaseStore
import context_filter
import wp_fetcher

API = "https://api.wordpress.org/plugins/info/1.2/"
UA = "WP-Research-Triage/0.1 (polite, read-only source scanner)"
MAX_ZIP_BYTES = 100 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024


class NonRetryableScanError(ValueError):
    """A permanent source or configured-limit rejection for the current plugin version."""


# These are source review leads, deliberately not vulnerability verdicts.
RULES = [
    ("wpdb-superglobal", re.compile(r"\$wpdb\s*->\s*(?:query|get_results|get_var|get_row)\s*\([^;]{0,500}\$_(?:GET|POST|REQUEST)", re.I | re.S), "Potential user input reaching a database call; inspect escaping and prepare() flow.", "sql_injection"),
    ("unserialize-superglobal", re.compile(r"\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST)", re.I), "Request data is passed directly to PHP deserialization; verify a usable gadget and impact.", "php_object_injection_with_gadget"),
    ("file-write-input", re.compile(r"\b(?:file_put_contents|fopen)\s*\([^,]{0,250}\$_(?:GET|POST|REQUEST)", re.I | re.S), "Potential request input reaching a file write; inspect path validation and reachability.", "arbitrary_file_upload"),
    ("php-upload-input", re.compile(r"\bmove_uploaded_file\s*\(\s*\$_FILES", re.I), "Upload handling receives a user file; verify extension/content controls and whether executable PHP can be written.", "arbitrary_php_file_upload"),
    ("file-delete-input", re.compile(r"\b(?:unlink|rmdir)\s*\([^)]{0,300}\$_(?:GET|POST|REQUEST)", re.I | re.S), "Request data appears in a file deletion path; verify traversal controls and impact.", "arbitrary_file_deletion"),
    ("dynamic-include-input", re.compile(r"\b(?:include|require)(?:_once)?\s*(?:\(\s*)?[^;]{0,300}\$_(?:GET|POST|REQUEST)", re.I | re.S), "Request data appears in an include path; verify whether local files can be selected.", "local_file_inclusion"),
    ("dynamic-code-input", re.compile(r"\b(?:eval|system|exec|shell_exec|passthru)\s*\([^)]{0,300}\$_(?:GET|POST|REQUEST)", re.I | re.S), "Request data appears to reach a code or command execution sink; trace validation and reachability.", "remote_code_execution"),
]

SOURCE_EXTENSIONS = {".php", ".py", ".go", ".rs"}


def local_rules_path():
    candidates = [
        Path(__file__).resolve().parent / "rules" / "wordpress_multilang.yml",
        Path(sysconfig.get_path("data")) / "share" / "phots" / "rules" / "wordpress_multilang.yml",
        Path(site.getuserbase()) / "share" / "phots" / "rules" / "wordpress_multilang.yml",
    ]
    return next((candidate for candidate in candidates if candidate.is_file()), candidates[0])


LOCAL_RULES = local_rules_path()

VULN_LABELS = {
    "sql_injection": "SQL injection",
    "stored_xss": "Stored cross-site scripting (XSS)",
    "xss_output": "Unescaped output / possible XSS",
    "remote_code_execution": "Command or code execution",
    "local_file_inclusion": "Local file inclusion",
    "directory_traversal": "Directory traversal / unsafe file path",
    "arbitrary_php_file_upload": "Potential unsafe PHP file upload",
    "arbitrary_file_upload": "Potential unsafe file upload",
    "arbitrary_file_deletion": "Potential arbitrary file deletion",
    "arbitrary_options_update": "Potential sensitive setting change",
    "privilege_escalation_to_admin": "Potential administrator privilege escalation",
    "php_object_injection_with_gadget": "Unsafe object deserialization",
}

REVIEW_PRIORITY_LABELS = {
    "P1": "P1 — highest review priority",
    "P2": "P2 — high review priority",
    "P3": "P3 — standard review priority",
    "UNCLASSIFIED": "Unclassified — priority not assigned",
}

REVIEW_PRIORITY_BASIS = {
    "P1": "high-impact vulnerability class; confirm reachability and impact",
    "P2": "potential SQL injection or XSS class; validate the affected context and impact",
    "P3": "other recognized security class; assess exploitability and context",
    "UNCLASSIFIED": "no recognized vulnerability class; manually classify the lead",
}

REVIEW_PRIORITY_P2_CLASSES = COMMON_DANGEROUS | {"xss_output"}
REVIEW_PRIORITY_P3_CLASSES = OTHER_IN_SCOPE | {"authorization_bypass"}


def review_priority(record):
    """Rank review order by potential impact class, not confirmed vulnerability severity."""
    hint = record.get("class_hint")
    scope = record.get("scope_decision") or {}
    existing_priority = record.get("priority")
    tier = scope.get("tier_class")
    if hint in HIGH_THREAT or tier == "high_threat" or existing_priority == "P1_HIGH_THREAT":
        code = "P1"
    elif hint in REVIEW_PRIORITY_P2_CLASSES or tier == "common_dangerous" or existing_priority == "P2_COMMON_DANGEROUS":
        code = "P2"
    elif hint in REVIEW_PRIORITY_P3_CLASSES or tier == "standard_other" or existing_priority == "P3_STANDARD_OTHER":
        code = "P3"
    else:
        code = "UNCLASSIFIED"
    return {"code": code, "label": REVIEW_PRIORITY_LABELS[code],
            "basis": REVIEW_PRIORITY_BASIS[code]}


def report_bucket(record):
    """Use review urgency labels; these are not vulnerability severity ratings."""
    ai_review = record.get("ai_review") or {}
    if ai_review.get("auto_closed"):
        return "AI closed as likely false positive"
    if ai_review.get("disposition") == "likely_bug":
        return "AI bug candidate — unconfirmed"
    if ai_review.get("disposition") == "likely_false_positive":
        return "AI false-positive suggestion — not closed"
    if ai_review.get("disposition") == "needs_human":
        return "AI review needs human follow-up"
    if ai_review.get("disposition") == "not_reviewed_limit":
        return "AI review cap — lead remains open"
    if record.get("scope_decision", {}).get("decision") == "PASS":
        return "Eligible candidate — human review required"
    hint = record.get("class_hint")
    confidence = str(record.get("confidence", "low")).lower()
    if hint and confidence in {"high", "very high"}:
        return "Review first — stronger automated signal"
    if hint:
        return "Review — plausible security lead"
    return "Unclassified — needs manual triage"


def plain_explanation(record):
    label = VULN_LABELS.get(record.get("class_hint"), "Potential security issue")
    engine = "Semgrep data-flow analysis" if record.get("engine") == "semgrep" else "pattern-based scan"
    return (f"The {engine} flagged code that may relate to {label}. "
            "This is a lead only; the scanner has not proved attacker reachability or impact.")


def ai_disposition_label(record):
    review = record.get("ai_review") or {}
    disposition = review.get("disposition")
    if not disposition:
        return "Not AI triaged"
    labels = {"likely_bug": "AI bug candidate · unconfirmed",
              "likely_false_positive": "AI false-positive suggestion · not closed",
              "needs_human": "AI review needs human follow-up",
              "not_reviewed_limit": "Not AI reviewed · per-plugin cap"}
    label = labels.get(disposition, "AI review pending")
    if review.get("auto_closed"):
        label = "AI closed as likely false positive · high confidence + source quote checked"
    error = f" Error: {review['error']}" if review.get("error") else ""
    return f"{label} ({review.get('confidence', 'unknown')} confidence): {review.get('summary', '')}{error}"


def ai_evidence_label(record):
    evidence = (record.get("ai_review") or {}).get("evidence", [])
    if not evidence:
        return "No source-verified AI quote."
    return "; ".join("{}:{} quote: {}".format(item.get("file"), item.get("line"), item.get("quote"))
                       for item in evidence[:3])


def make_ai_reviewer(args, db_path: Path):
    if not getattr(args, "ai_triage", False):
        return None
    load_env_file()
    try:
        config = AIConfig(base_url=getattr(args, "ai_base_url", None),
                          model=getattr(args, "ai_model", None))
        config.require_configured()
    except (RuntimeError, ValueError) as exc:
        print(f"AI triage is unavailable ({exc}); continuing without AI.", file=sys.stderr)
        return None
    return AIReviewer(config, AIMemory(db_path))


def configure_ai_interactively():
    if not sys.stdin.isatty():
        raise RuntimeError("AI setup requires an interactive terminal.")
    load_env_file()
    current = AIConfig()
    print("Configure optional AI lead triage (OpenAI-compatible endpoint).")
    base_url = input(f"Base URL [{current.base_url}]: ").strip() or current.base_url
    model = input(f"Model [{current.model}]: ").strip() or current.model
    api_key = getpass.getpass("API key (leave blank to keep the current key): ").strip()
    config = AIConfig(base_url=base_url, model=model, api_key=api_key or None)
    config.require_configured()
    saved_path = save_ai_settings(config.base_url, config.model, api_key or None)
    print(f"AI settings saved to {saved_path}. The API key was not displayed.")


def ensure_history_schema(db):
    """Create or migrate Phots' persistent per-plugin scan history."""
    db.execute("""CREATE TABLE IF NOT EXISTS completed (
        slug TEXT NOT NULL, version TEXT NOT NULL, name TEXT, installs INTEGER,
        completed_at TEXT NOT NULL, source_fingerprint TEXT,
        PRIMARY KEY(slug,version))""")
    columns = {row[1] for row in db.execute("PRAGMA table_info(completed)")}
    if "source_fingerprint" not in columns:
        db.execute("ALTER TABLE completed ADD COLUMN source_fingerprint TEXT")
    db.execute("""CREATE TABLE IF NOT EXISTS signals (
        signal_id TEXT PRIMARY KEY, slug TEXT NOT NULL, version TEXT NOT NULL,
        name TEXT, installs INTEGER, record TEXT NOT NULL, completed_at TEXT NOT NULL)""")
    db.execute("CREATE INDEX IF NOT EXISTS signals_plugin_version_idx ON signals(slug,version)")
    db.execute("""CREATE TABLE IF NOT EXISTS stream_meta (
        key TEXT PRIMARY KEY, value TEXT NOT NULL)""")
    db.commit()


def fingerprint_source(root: Path, max_files: int | None = None) -> str:
    """Hash supported, scannable source files in a stable order for drift checks."""
    digest = hashlib.sha256()
    candidates = (p for p in root.rglob("*")
                  if p.is_file() and p.suffix.lower() in SOURCE_EXTENSIONS
                  and p.stat().st_size <= MAX_FILE_BYTES)
    key = lambda p: p.relative_to(root).as_posix().casefold()
    candidates = (heapq.nsmallest(max_files, candidates, key=key)
                  if max_files is not None else sorted(candidates, key=key))
    for path in candidates:
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8", errors="replace"))
        digest.update(b"\0")
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(128 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    digest.update(f"files:{len(candidates)}".encode())
    return digest.hexdigest()


def latest_completed(db):
    saved = db.execute("SELECT value FROM stream_meta WHERE key='last_plugin'").fetchone()
    if saved:
        try:
            return json.loads(saved[0])
        except (TypeError, json.JSONDecodeError):
            pass
    row = db.execute("SELECT slug,version,completed_at FROM completed ORDER BY completed_at DESC LIMIT 1").fetchone()
    if not row:
        return None
    return {"slug": row[0], "version": row[1], "completed_at": row[2]}


def write_memory_snapshot(out: Path, db):
    latest = latest_completed(db)
    completed_count = db.execute("SELECT COUNT(*) FROM completed").fetchone()[0]
    fingerprint_count = db.execute(
        "SELECT COUNT(*) FROM completed WHERE source_fingerprint IS NOT NULL").fetchone()[0]
    atomic_json(out / "phots-memory.json", {
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "completed_plugin_versions": completed_count,
        "versions_with_drift_baseline": fingerprint_count,
        "last_completed": latest,
        "history_database": "phots_stream.sqlite3",
        "normal_scans_skip_completed_versions": True,
        "drift_scan_mode": "python scanner.py drift",
    })


def save_plugin_completion(db, plugin: dict, findings: list[dict], source_hash: str | None,
                           completed_at: str | None = None):
    """Persist current signals and completion state; drift rescans replace stale signals."""
    slug = str(plugin["slug"])
    version = str(plugin["version"])
    completed_at = completed_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    installs = int(plugin.get("active_installs", 0) or 0)
    name = str(plugin.get("name") or slug)
    db.execute("DELETE FROM signals WHERE slug=? AND version=?", (slug, version))
    for finding in findings:
        finding["scope_decision"] = evaluate_scope({
            "asset_type": "plugin", "active_installs": installs,
            "vulnerability_type": finding.get("class_hint"), "review_status": "unreviewed",
        }).copy()
        finding["priority"] = "UNCLASSIFIED"
        finding["review_priority"] = review_priority(finding)["code"]
        db.execute("INSERT OR REPLACE INTO signals VALUES (?,?,?,?,?,?,?)",
                   (finding["signal_id"], slug, version, name, installs,
                    json.dumps(finding, ensure_ascii=False), completed_at))
    db.execute("""INSERT OR REPLACE INTO completed
        (slug,version,name,installs,completed_at,source_fingerprint) VALUES (?,?,?,?,?,?)""",
        (slug, version, name, installs, completed_at, source_hash))
    db.execute("INSERT OR REPLACE INTO stream_meta(key,value) VALUES ('last_plugin',?)",
               (json.dumps({"slug": slug, "version": version, "completed_at": completed_at}),))
    db.commit()


def write_human_report(out: Path, plugins: list[dict], decisions: list[dict], alerts: list[dict],
                       failures: int, semgrep_failures: int, elapsed: float,
                       stream_status: dict | None = None, html_path: Path | None = None,
                       write_markdown: bool = True):
    catalog = {p["slug"]: p for p in plugins}
    buckets = {}
    priority_buckets = {}
    class_counts = {}
    for record in decisions:
        buckets.setdefault(report_bucket(record), []).append(record)
        priority = review_priority(record)
        record["review_priority"] = priority["code"]
        priority_buckets.setdefault(priority["code"], []).append(record)
        class_label = VULN_LABELS.get(record.get("class_hint"), "Unclassified security pattern")
        class_counts[class_label] = class_counts.get(class_label, 0) + 1
    order = ["AI bug candidate — unconfirmed", "AI review needs human follow-up",
             "AI false-positive suggestion — not closed", "AI review cap — lead remains open", "Review first — stronger automated signal",
             "Review — plausible security lead", "Unclassified — needs manual triage",
             "AI closed as likely false positive", "Eligible candidate — human review required"]
    priority_order = ["P1", "P2", "P3", "UNCLASSIFIED"]
    lines = ["# WordPress Plugin Scan Report", "",
             "> Automated source review produces leads, not confirmed vulnerabilities or severity ratings. Review priorities are class-based triage aids, not CVSS scores or confirmed severity.", "",
             "## At a glance", "",
             f"- Plugins in this run: **{stream_status.get('scanned', len(plugins)) if stream_status else len(plugins)}**",
             f"- Candidate signals: **{stream_status.get('signal_count', len(decisions)) if stream_status else len(decisions)}**",
             f"- Context-suppressed leads: **{stream_status.get('context_suppressed', 0) if stream_status else 0}** (auto-cleared false positives)",
             f"- Eligible candidates: **{len(alerts)}** (still require human verification)",
             f"- Download/scan failures: **{failures}**",
             f"- Semgrep unavailable/error runs: **{semgrep_failures}**",
             f"- Elapsed: **{elapsed:.1f} seconds**", "",
             "## Suggested review priority (not vulnerability severity)", ""]
    for code in priority_order:
        lines.append(f"- **{REVIEW_PRIORITY_LABELS[code]}:** "
                     f"{len(priority_buckets.get(code, []))} — {REVIEW_PRIORITY_BASIS[code]}")
    lines += ["", "## Leads by vulnerability class", ""]
    lines.extend(f"- **{label}:** {count}" for label, count in sorted(class_counts.items()))
    if not class_counts:
        lines.append("No lead categories in this report.")
    lines += ["", "## Review groups (AI and signal status)", ""]
    ai_counts = {}
    for record in decisions:
        review = record.get("ai_review") or {}
        if review.get("disposition"):
            ai_counts[review["disposition"]] = ai_counts.get(review["disposition"], 0) + 1
    if ai_counts:
        lines.insert(6, "- **AI triage in this report window:** " + ", ".join(
            f"{key}: {value}" for key, value in sorted(ai_counts.items())))
    if stream_status:
        lines[2:2] = ["## Phots live stream", "",
                      f"- **Status:** {stream_status.get('status', 'running')}",
                      f"- **Started:** {stream_status.get('started_at', 'unknown')}",
                      f"- **Last plugin completed:** {stream_status.get('last_plugin', 'none yet')}",
                      f"- **Last heartbeat:** {stream_status.get('last_updated', 'starting')}",
                      f"- **Current activity:** {'; '.join(stream_status.get('active_jobs', [])) or 'waiting for catalog changes'}",
                      f"- **Retry status:** {stream_status.get('retry_note', 'no retries pending')}",
                      f"- **Latest issue:** {stream_status.get('last_error', 'none')}",
                      f"- **Semgrep detail:** {stream_status.get('last_semgrep_error', 'none')}",
                      f"- **Feed note:** {stream_status.get('scan_note', 'none')}",
                      f"- **Resource recommendation:** {stream_status.get('recommendation', 'unknown')}",
                      f"- **Streams in use:** {stream_status.get('workers', '?')}",
             f"- **Available memory:** {stream_status.get('current_memory_gb', stream_status.get('available_memory_gb', '?'))} GiB now; {stream_status.get('available_memory_gb', '?')} GiB at startup", ""]
        lines.insert(2, f"- **Report window:** latest {stream_status.get('report_limit', 250)} signals; full history is in SQLite")
        stream_status["report_buckets"] = {name: len(buckets.get(name, [])) for name in order}
        stream_status["priority_buckets"] = {code: len(priority_buckets.get(code, []))
                                             for code in priority_order}
        stream_status["class_buckets"] = class_counts
    for bucket in order:
        lines.append(f"- **{bucket}:** {len(buckets.get(bucket, []))}")
    if not decisions:
        lines += ["", "No candidate signals were found in the scanned source. This does not prove the plugins are free of vulnerabilities."]
    for code in priority_order:
        records = priority_buckets.get(code, [])
        if not records:
            continue
        lines += ["", f"## {REVIEW_PRIORITY_LABELS[code]}", "",
                  REVIEW_PRIORITY_BASIS[code], ""]
        for index, item in enumerate(records, 1):
            meta = catalog.get(item["plugin_slug"], {})
            display = meta.get("name") or item["plugin_slug"]
            decision = item.get("scope_decision", {})
            priority = review_priority(item)
            scope = decision.get("decision", "REVIEW")
            why = "; ".join(decision.get("reasons", [])) or "Required eligibility evidence has not been reviewed."
            lines += [f"### {index}. {display} ({item['plugin_slug']})",
                      f"- **What was flagged:** {VULN_LABELS.get(item.get('class_hint'), 'Unclassified security pattern')}",
                      f"- **Suggested review priority:** {priority['label']} — {priority['basis']}",
                      f"- **AI review:** {ai_disposition_label(item)}",
                      f"- **AI evidence:** {ai_evidence_label(item)}",
                      f"- **Where:** `{item.get('file', '?')}:{item.get('line', '?')}` ({item.get('language', '?')})",
                      f"- **Signal source:** {item.get('engine', 'unknown')} · confidence label: {item.get('confidence', 'unknown')}",
                      f"- **In plain language:** {plain_explanation(item)}",
                      f"- **Scope filter:** {scope} — {why}",
                      f"- **Next step:** Trace attacker-controlled input to the flagged operation; check authentication/capability and nonce protections, sanitization/escaping, real impact, affected version, and duplicate status.",
                      f"- **Signal ID:** `{item.get('signal_id', '')}`", "",
                      "```text", str(item.get("excerpt", "(no excerpt)"))[:360], "```", ""]
    if write_markdown:
        (out / "report.md").write_text("\n".join(lines), encoding="utf-8")

    # A lightweight HTML view makes the same report scannable in a browser.
    cards = []
    for code in priority_order:
        for item in priority_buckets.get(code, []):
            decision = item.get("scope_decision", {})
            meta = catalog.get(item["plugin_slug"], {})
            priority = review_priority(item)
            cards.append(f"<article><h2>{html.escape(str(meta.get('name') or item['plugin_slug']))}</h2>"
                         f"<p><b>{html.escape(priority['label'])}</b> · "
                         f"{html.escape(report_bucket(item))} · {html.escape(str(decision.get('decision', 'REVIEW')))} · "
                         f"{html.escape(VULN_LABELS.get(item.get('class_hint'), 'Unclassified security pattern'))}</p>"
                         f"<p><b>Suggested review priority:</b> {html.escape(priority['label'])} — "
                         f"{html.escape(priority['basis'])}</p>"
                         f"<p><b>AI:</b> {html.escape(ai_disposition_label(item))}</p>"
                         f"<p><b>AI evidence:</b> {html.escape(ai_evidence_label(item))}</p>"
                         f"<p>{html.escape(plain_explanation(item))}</p>"
                         f"<p><code>{html.escape(str(item.get('file')))}:{item.get('line')} ({html.escape(str(item.get('language')))}; {html.escape(str(item.get('engine')))}; {html.escape(str(item.get('confidence')))})</code></p>"
                         f"<pre>{html.escape(str(item.get('excerpt', ''))[:360])}</pre>"
                         f"<p>Next: trace input to operation, verify access controls and impact, then check affected version and duplicates.</p>"
                         f"<details><summary>Scope filter details</summary><p>{html.escape('; '.join(decision.get('reasons', [])))}</p></details></article>")
    page = ("<!doctype html><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
            "<title>Plugin scan report</title><style>body{font:16px system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#172033;background:#f5f7fb}"
            "article{background:white;padding:1rem 1.25rem;margin:1rem 0;border-radius:12px;border:1px solid #dce3ef}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f8;padding:.8rem;border-radius:8px}"
            ".note{background:#fff5d6;padding:1rem;border-radius:8px}</style>"
            "<h1>WordPress Plugin Scan Report</h1><p class='note'>Automated leads only; not confirmed vulnerabilities or severity ratings. Review priorities are class-based triage aids, not CVSS scores.</p>"
            f"<p>{stream_status.get('scanned', len(plugins)) if stream_status else len(plugins)} plugins · {stream_status.get('signal_count', len(decisions)) if stream_status else len(decisions)} signals · {len(alerts)} eligible candidates pending human verification · {failures} scan failures</p>"
            + "".join(f"<p><b>{html.escape(REVIEW_PRIORITY_LABELS[code])}:</b> {len(priority_buckets.get(code, []))}</p>"
                      for code in priority_order)
            + "<h2>Leads by vulnerability class</h2>"
            + "".join(f"<p><b>{html.escape(label)}:</b> {count}</p>"
                      for label, count in sorted(class_counts.items()))
            + "".join(f"<p><b>{html.escape(name)}:</b> {len(buckets.get(name, []))}</p>" for name in order)
            + "".join(cards))
    if stream_status:
        page = page.replace("<meta charset='utf-8'>", "<meta charset='utf-8'><meta http-equiv='refresh' content='10'>")
        banner = ("<section style='background:#e8f3ff;padding:1rem;border-radius:10px'><h2>Phots live stream</h2>"
                  f"<p>Status: {html.escape(str(stream_status.get('status')))} · Started: {html.escape(str(stream_status.get('started_at')))}</p>"
                  f"<p>Last completed: {html.escape(str(stream_status.get('last_plugin')))} · Streams: {stream_status.get('workers')} · "
                  f"Available memory: {stream_status.get('current_memory_gb', stream_status.get('available_memory_gb'))} GiB now; startup was {stream_status.get('available_memory_gb')} GiB</p>"
                  f"<p>Recommendation: {html.escape(str(stream_status.get('recommendation')))}</p>"
                  f"<p>Last heartbeat: {html.escape(str(stream_status.get('last_updated', 'starting')))} · Current activity: {html.escape('; '.join(stream_status.get('active_jobs', [])) or 'waiting for catalog changes')}</p>"
                  f"<p>Retry status: {html.escape(str(stream_status.get('retry_note', 'no retries pending')))}</p>"
                  f"<p>Latest issue: {html.escape(str(stream_status.get('last_error', 'none')))}</p>"
                  f"<p>Semgrep detail: {html.escape(str(stream_status.get('last_semgrep_error', 'none')))}</p>"
                  f"<p>Feed note: {html.escape(str(stream_status.get('scan_note', 'none')))}</p>"
                  f"<p>Showing latest {stream_status.get('report_limit', 250)} signals; complete history is in SQLite.</p></section>")
        page = page.replace("<h1>WordPress Plugin Scan Report</h1>", "<h1>WordPress Plugin Scan Report</h1>" + banner)
    target = html_path or (out / "report.html")
    atomic_write_text(target, page)


def _cgroup_memory_available_bytes():
    """Return cgroup-v1/v2 memory headroom, or None when not running in a limited cgroup."""
    candidates = [
        (Path("/sys/fs/cgroup/memory.max"), Path("/sys/fs/cgroup/memory.current")),
        (Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
         Path("/sys/fs/cgroup/memory/memory.usage_in_bytes")),
    ]
    for limit_path, usage_path in candidates:
        try:
            limit_text = limit_path.read_text(encoding="ascii").strip()
            if limit_text == "max":
                continue
            limit, usage = int(limit_text), int(usage_path.read_text(encoding="ascii").strip())
            # cgroup v1 represents an unlimited limit as a very large sentinel.
            if limit > 1 << 60:
                continue
            return max(0, limit - usage)
        except (OSError, ValueError):
            continue
    return None


def memory_available_bytes():
    """Return usable memory, respecting a Linux container's cgroup limit."""
    available = None
    if os.name == "nt":
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        state = MEMORYSTATUSEX()
        state.dwLength = ctypes.sizeof(state)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(state)):
            available = int(state.ullAvailPhys)
    else:
        try:
            pages = os.sysconf("SC_AVPHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            available = int(pages * page_size)
        except (ValueError, OSError, AttributeError):
            pass
    cgroup_available = _cgroup_memory_available_bytes()
    if cgroup_available is not None:
        available = min(available, cgroup_available) if available is not None else cgroup_available
    return available


def available_cpu_count():
    """Return a CPU count bounded by Linux cgroup quota where available."""
    cores = max(1, os.cpu_count() or 1)
    for quota_path, period_path in (
        (Path("/sys/fs/cgroup/cpu.max"), None),
        (Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"), Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us")),
    ):
        try:
            if period_path is None:
                quota, period = quota_path.read_text(encoding="ascii").split()[:2]
                if quota == "max":
                    continue
                quota, period = int(quota), int(period)
            else:
                quota, period = int(quota_path.read_text(encoding="ascii").strip()), int(
                    period_path.read_text(encoding="ascii").strip())
            if quota > 0 and period > 0:
                cores = min(cores, max(1, quota // period))
        except (OSError, ValueError):
            continue
        break
    return cores


def concurrency_recommendation(max_workers: int, semgrep_enabled: bool):
    available = memory_available_bytes()
    cores = available_cpu_count()
    # Reserve 35% of current free RAM for the OS and unrelated applications.
    per_worker = 2 * 1024**3 if semgrep_enabled else 512 * 1024**2
    memory_slots = max(1, int((available * 0.65) // per_worker)) if available else 1
    recommended = max(1, min(max_workers, cores, memory_slots))
    available_gb = round(available / 1024**3, 1) if available is not None else None
    basis = f"{cores} logical CPU cores; reserve 35% of free RAM; budget {per_worker // 1024**2} MiB per stream"
    return recommended, available_gb, basis


def atomic_write_text(path: Path, text: str, attempts: int = 5):
    """Atomically replace a file, tolerating transient Windows/OneDrive file locks."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        for attempt in range(attempts):
            try:
                os.replace(temp, path)
                return
            except PermissionError:
                if attempt + 1 == attempts:
                    raise
                time.sleep(0.1 * (attempt + 1))
    finally:
        temp.unlink(missing_ok=True)


def atomic_json(path: Path, value):
    atomic_write_text(path, json.dumps(value, indent=2, ensure_ascii=False))


class PhotsLiveLog:
    """Append-only operational log plus a compact, designer-friendly handoff snapshot."""

    def __init__(self, log_path: Path, handoff_path: Path):
        self.log_path = Path(log_path)
        self.handoff_path = Path(handoff_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.handoff_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.max_bytes = 10 * 1024 * 1024

    @staticmethod
    def _safe(value):
        value = str(value)
        value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+=*", r"\1[REDACTED]", value)
        value = re.sub(r"(?i)((?:api[_-]?key|secret|token|password)\s*[:=]\s*)[^\s,;]+",
                       r"\1[REDACTED]", value)
        return value[:800]

    def event(self, level: str, event: str, **fields):
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        details = " ".join(f"{key}={self._safe(value)}" for key, value in fields.items() if value is not None)
        line = f"{timestamp} [{level.upper()}] {event}" + (f" {details}" if details else "") + "\n"
        with self.lock:
            try:
                if self.log_path.exists() and self.log_path.stat().st_size + len(line.encode("utf-8")) > self.max_bytes:
                    backup = self.log_path.with_suffix(self.log_path.suffix + ".1")
                    backup.unlink(missing_ok=True)
                    self.log_path.replace(backup)
                with self.log_path.open("a", encoding="utf-8", newline="\n") as stream:
                    stream.write(line)
                    stream.flush()
            except OSError:
                pass

    def recent_events(self, limit=80):
        rows = []
        for path in (self.log_path.with_suffix(self.log_path.suffix + ".1"), self.log_path):
            try:
                rows.extend(path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:])
            except OSError:
                continue
        return rows[-limit:]

    def update_handoff(self, state: dict):
        notes = []
        if state.get("workers", 0) > state.get("recommended", 0):
            notes.append(
                f"Configured concurrency is {state['workers']} streams, above the RAM-based "
                f"recommendation of {state['recommended']}; currently {state.get('active', 0)} "
                f"active and {state.get('queued', 0)} queued. More concurrent work may increase peak RAM use."
            )
        if state.get("active", 0) == 0 and state.get("queued", 0) == 0 and "waiting" in str(state.get("status", "")):
            notes.append("Idle is expected only while polling the catalog; check the feed note and next-poll countdown if no plugins are found.")
        if state.get("semgrep_failures", 0):
            notes.append(f"Semgrep errors observed: {state['semgrep_failures']}. See latest Semgrep detail below.")
        if state.get("failures", 0):
            notes.append(f"Plugin download/scan failures observed: {state['failures']}. Review retries and archive/resource limits.")
        if state.get("ai_enabled"):
            notes.append("AI triage is enabled. Treat bug candidates as unconfirmed; verify false-positive closures before relying on them.")
            if state.get("ai_needs_human", 0):
                notes.append(f"AI has {state['ai_needs_human']} leads awaiting human review.")
            if state.get("ai_errors", 0):
                notes.append(f"AI endpoint errors: {state['ai_errors']}; latest: {state.get('last_ai_error', 'unknown')}")
        if not notes:
            notes.append("No operational errors are currently reported. Review the recent event log for timing and progress patterns.")
        recent = self.recent_events()
        lines = ["# Phots Designer Handoff", "",
                 "> Live operational snapshot for product/design review. It contains status and event metadata, not source excerpts or API keys.", "",
                 "## Run snapshot", "",
                 f"- Status: {state.get('status', 'unknown')}",
                 f"- Started: {state.get('started_at', 'unknown')}",
                 f"- Last updated: {state.get('last_updated', 'unknown')}",
                 f"- Uptime: {state.get('uptime', 'unknown')}",
                 f"- Plugins scanned: {state.get('scanned', 0)}; signals: {state.get('signal_count', 0)}",
                 f"- Workers active/queued: {state.get('active', 0)}/{state.get('queued', 0)}; configured streams: {state.get('workers', 0)}",
                 f"- RAM now/start: {state.get('current_memory_gb', 'unknown')}/{state.get('available_memory_gb', 'unknown')} GiB",
                 f"- Recommended streams: {state.get('recommended', 'unknown')} (max {state.get('max_workers', 'unknown')})",
                 f"- Semgrep errors: {state.get('semgrep_failures', 0)}; latest detail: {state.get('last_semgrep_error', 'none')}",
                 f"- AI triage: {'enabled (' + str(state.get('ai_model')) + ')' if state.get('ai_enabled') else 'disabled'}; reviewed {state.get('ai_reviewed', 0)}; closed as likely false positive {state.get('ai_closed', 0)}; bug candidates {state.get('ai_bug_candidates', 0)}; human follow-up {state.get('ai_needs_human', 0)}",
                 f"- AI endpoint errors: {state.get('ai_errors', 0)}; latest: {state.get('last_ai_error', 'none')}",
                 f"- Latest plugin: {state.get('last_plugin', 'none')}",
                 f"- Current activity: {'; '.join(state.get('active_jobs', [])) or 'idle'}",
                 f"- Feed note: {state.get('scan_note', 'none')}",
                 f"- Latest error: {state.get('last_error', 'none')}",
                 f"- Retry: {state.get('retry_note', 'none')}",
                 f"- Live report: {state.get('report_path', 'unknown')}",
                 f"- Live log: {self.log_path}", "",
                 "## Review notes for the Phots designer", ""]
        lines.extend(f"- {note}" for note in notes)
        lines += ["", "## Recent live events", "", "```text"]
        lines.extend(recent or ["No events recorded yet."])
        lines += ["```", "", "## Interpretation", "",
                  "Automated scan counts and AI dispositions are workflow telemetry, not confirmed vulnerabilities. A quiet period with status `waiting` means the feed returned no unseen eligible versions until the next poll; active worker stages and elapsed times distinguish slow work from idle polling.", ""]
        try:
            atomic_write_text(self.handoff_path, "\n".join(lines))
        except OSError:
            pass


def terminal_size():
    try:
        import shutil as _shutil
        return _shutil.get_terminal_size((100, 30))
    except OSError:
        return type("Size", (), {"columns": 100, "lines": 30})()


def draw_phots_tui(state: dict, recent: list[dict], *, paused: bool = False):
    """Render a dependency-free, ANSI dashboard that works in modern Windows terminals."""
    if not sys.stdout.isatty():
        return
    width = max(60, min(110, terminal_size().columns - 2))
    inner = width - 4
    cyan, blue, green, yellow, muted, reset = "\x1b[96m", "\x1b[94m", "\x1b[92m", "\x1b[93m", "\x1b[90m", "\x1b[0m"

    def clip(value, limit=inner):
        value = re.sub(r"\s+", " ", str(value))
        return value if len(value) <= limit else value[:max(1, limit - 1)] + "…"

    def box(title, rows, color=cyan):
        top = f"┌─ {title} " + "─" * max(0, width - len(title) - 5) + "┐"
        return [color + top + reset] + [f"│ {clip(row):<{inner}} │" for row in rows] + [color + "└" + "─" * (width - 2) + "┘" + reset]

    def worker_meter(active, total, length=16):
        filled = round(length * min(active, total) / max(total, 1))
        return "[" + "█" * filled + "·" * (length - filled) + "]"

    latest = recent[-4:]
    findings = [
        f"{r.get('plugin_slug', 'plugin')} · {r.get('class_hint') or 'unclassified'} · "
        f"{r.get('file', '?')}:{r.get('line', '?')}"
        for r in latest
    ]
    if not findings:
        findings = list(state.get("recent_signal_lines", []))[-4:]
    if not findings:
        findings = ["No leads yet — Phots will show review candidates here."]
    workers = max(1, int(state.get("workers", 1) or 1))
    active = max(0, int(state.get("active", 0) or 0))
    queued = max(0, int(state.get("queued", 0) or 0))
    frame = "|/-\\"[int(time.monotonic() * 4) % 4]
    phase = "PAUSED" if paused else str(state.get("status", "starting"))
    phase_color = yellow if paused or "waiting" in phase.lower() else green
    activity_mark = frame if active or phase.lower() in {"running", "starting"} else "·"
    headline = [
        f"{cyan}PHOTS  /  WORDPRESS PLUGIN RESEARCH{reset}",
        f"{muted}Welcome. Follow each source-review lead with human validation; signals are not confirmed bugs.{reset}",
        f"{muted}Discover releases  →  inspect source locally  →  remember completed versions  →  review leads{reset}",
    ]
    body = []
    body.extend(box("LIVE SCAN", [
        f"{activity_mark} {phase_color}{phase}{reset}  {worker_meter(active, workers)}  "
        f"{active}/{workers} active · {queued} queued",
        f"Completed versions: {state.get('scanned', 0)}  ·  Review leads: {state.get('signal_count', 0)}  ·  "
        f"Errors: {state.get('failures', 0)}  ·  Uptime: {state.get('uptime', '0s')}",
        f"Last completed: {state.get('last_plugin') or 'waiting for first plugin'}",
        f"AI triage: {'on · ' + str(state.get('ai_model')) if state.get('ai_enabled') else 'off'}  ·  "
        f"Semgrep: {'available' if state.get('semgrep_available') else 'not detected'}",
    ], green))
    activity = state.get("job_lines") or ["Waiting for the next catalog check."]
    body.extend(box("CURRENT ACTIVITY", activity[:4], cyan))
    body.extend(box("SYSTEM & OUTPUT", [
        f"Discovery: {state.get('discovery_feed', 'WordPress.org')}",
        f"Free RAM: {state.get('current_memory_gb', state.get('available_memory_gb', 'unknown'))} GiB  ·  "
        f"Configured/recommended workers: {workers}/{state.get('recommended', 1)} "
        f"(max {state.get('max_workers', 10)})",
        f"Feed poll: every {state.get('poll_seconds', 30)}s  ·  Output: {state.get('report_path', 'output/phots-live-report.html')}",
    ], blue))
    body.extend(box("LATEST SIGNALS · leads, not confirmed bugs", findings, yellow))
    body.extend([
        f"{muted}P pause/resume · Q quit cleanly · Ctrl+C stop and save · drift checks are a separate scan mode{reset}",
        f"{muted}No plugin code is executed; the HTML report refreshes as work completes.{reset}",
    ])
    sys.stdout.write("\x1b[2J\x1b[H" + "\n".join(headline + body) + "\n")
    sys.stdout.flush()


def key_pressed():
    """Read a single key without blocking; used for the pause/resume convenience key."""
    if os.name == "nt":
        try:
            import msvcrt
            return msvcrt.getwch().lower() if msvcrt.kbhit() else None
        except ImportError:
            return None
    try:
        import select
        ready, _, _ = select.select([sys.stdin], [], [], 0)
        return sys.stdin.read(1).lower() if ready else None
    except (OSError, ValueError):
        return None


def retry_delay_seconds(attempt: int, error: Exception):
    if isinstance(error, NonRetryableScanError) or attempt >= 3:
        return None
    return min(60 * (2 ** max(0, attempt - 1)), 600)


def finish_interrupted_stream_run(store, run_id: str, state: dict, live_log):
    try:
        store.finish_run(
            run_id, "failed", scanned_plugins=state["scanned"],
            failed_plugins=state["failures"], signal_count=state["signal_count"],
            alert_count=0, timeout=5,
        )
    except KeyboardInterrupt:
        message = "Supabase stop update was interrupted; the remote run may remain marked running."
        state["supabase_error"] = message
        live_log.event("WARN", "supabase_stop_update_interrupted")
        print(f"Warning: {message}", file=sys.stderr)
    except Exception as exc:
        message = f"Supabase could not record the interrupted run: {exc}"[:300]
        state["supabase_error"] = message
        live_log.event("ERROR", "supabase_stop_update_failed", detail=exc)
        print(f"Warning: {message}", file=sys.stderr)


def stream(args):
    """Continuously discover unseen WordPress.org plugin versions and scan them."""
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    db_path = out / "phots_stream.sqlite3"
    ai_reviewer = make_ai_reviewer(args, db_path)
    report_path = Path(args.report) if args.report else out / "phots-live-report.html"
    if not report_path.is_absolute():
        report_path = Path.cwd() / report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    log_path = Path(args.log_file) if getattr(args, "log_file", None) else out / "phots-live.log"
    handoff_path = Path(args.handoff_file) if getattr(args, "handoff_file", None) else out / "phots-designer-handoff.md"
    if not log_path.is_absolute():
        log_path = Path.cwd() / log_path
    if not handoff_path.is_absolute():
        handoff_path = Path.cwd() / handoff_path
    live_log = PhotsLiveLog(log_path, handoff_path)
    max_workers = min(args.max_workers, 10)
    semgrep_enabled = bool(shutil.which("semgrep"))
    recommended, available_gb, basis = concurrency_recommendation(max_workers, semgrep_enabled)
    workers = args.workers or recommended
    workers = min(max_workers, workers)
    if workers > recommended:
        print(f"Phots note: {workers} streams exceeds the current RAM-based recommendation of {recommended}; "
              "Semgrep may increase memory pressure.", file=sys.stderr)
    option_fit = ", ".join(f"{n}: {'within recommendation' if n <= recommended else 'above recommendation'}"
                           for n in (1, 2, 3, 4, 10))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    search = (getattr(args, "search", None) or "").strip() or None
    selected_feed = feed_label(args.browse, search)
    state = {"started_at": now, "status": "running", "workers": workers,
             "recommended": recommended, "available_memory_gb": available_gb,
             "recommendation": basis, "stream_options": option_fit,
             "discovery_feed": selected_feed,
             "max_workers": max_workers, "report_path": str(report_path),
             "log_path": str(log_path), "handoff_path": str(handoff_path),
             "poll_seconds": args.poll_seconds, "scanned": 0, "signal_count": 0,
             "failures": 0, "last_plugin": None, "active": 0, "queued": 0,
             "semgrep_available": semgrep_enabled, "context_suppressed": 0}
    state["ai_enabled"] = bool(ai_reviewer)
    reviewed_clean_path = Path(getattr(args, "reviewed_clean", "output/reviewed_clean.json"))
    if not reviewed_clean_path.is_absolute():
        reviewed_clean_path = out / reviewed_clean_path.name
    reviewed_clean = context_filter.load_reviewed_clean(reviewed_clean_path)
    if ai_reviewer:
        state["ai_model"] = ai_reviewer.config.model
    store = SupabaseStore() if args.supabase else None
    run_id = str(uuid.uuid4())
    if store:
        store.verify()
        store.start_run(run_id, 0)
    with sqlite3.connect(db_path, timeout=30) as db:
        db.execute("PRAGMA journal_mode=WAL")
        ensure_history_schema(db)
        previous = latest_completed(db)
        if previous:
            state["last_plugin"] = f"{previous['slug']} {previous['version']}"

    def already_seen(slug, version):
        return db.execute("SELECT 1 FROM completed WHERE slug=? AND version=?", (slug, version)).fetchone() is not None

    progress_events = queue_module.SimpleQueue()
    jobs = {}
    def drain_progress():
        while True:
            try:
                event = progress_events.get_nowait()
            except queue_module.Empty:
                break
            previous = jobs.get(event["slug"], {})
            now_mono = time.monotonic()
            last_log = previous.get("last_log_at", 0)
            if event.get("phase") != previous.get("phase") or now_mono - last_log >= 30:
                live_log.event("INFO", "worker_progress", plugin=event["slug"],
                               phase=event.get("phase"), detail=event.get("detail"))
                last_log = now_mono
            jobs[event["slug"]] = {**event, "changed_at": now_mono, "last_log_at": last_log}
        job_lines, active_lines = [], []
        for slug, job in list(jobs.items()):
            age = int(time.monotonic() - job["changed_at"])
            activity = f"{slug}: {job['phase']} — {job.get('detail', '')} ({age}s in this step)"
            job_lines.append(activity)
            active_lines.append(activity)
        state["job_lines"] = job_lines[-workers:] or [
            f"Workers are idle; checking {state.get('discovery_feed', 'WordPress.org')}."
        ]
        state["active_jobs"] = active_lines[-workers:]

    def publish(latest_plugin=None):
        drain_progress()
        db.commit()
        state["uptime"] = f"{int(time.monotonic() - started)}s"
        state["last_updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        previous = latest_completed(db)
        if previous:
            state["last_plugin"] = f"{previous['slug']} {previous['version']}"
        free_now = memory_available_bytes()
        state["current_memory_gb"] = round(free_now / 1024**3, 1) if free_now is not None else "unknown"
        state["last_plugin"] = latest_plugin or state.get("last_plugin")
        state["active"] = sum(not f.done() for f in active_futures)
        total_plugins = db.execute("SELECT COUNT(*) FROM completed").fetchone()[0]
        total_signals = db.execute("SELECT COUNT(*) FROM signals").fetchone()[0]
        if ai_reviewer:
            triage_counts = dict(db.execute("SELECT disposition, COUNT(*) FROM ai_reviews GROUP BY disposition").fetchall())
            state["ai_reviewed"] = sum(triage_counts.values())
            fp_rows = db.execute("SELECT confidence,summary,evidence_json FROM ai_reviews WHERE disposition='likely_false_positive'").fetchall()
            state["ai_closed"] = sum(1 for confidence, summary, evidence in fp_rows
                                      if confidence == "high" and len(summary) >= 80
                                      and bool(json.loads(evidence)))
            state["ai_bug_candidates"] = triage_counts.get("likely_bug", 0)
            state["ai_needs_human"] = triage_counts.get("needs_human", 0)
        recent_rows = db.execute("SELECT record FROM signals ORDER BY completed_at DESC LIMIT 250").fetchall()
        recent_records = [json.loads(r[0]) for r in reversed(recent_rows)]
        state["recent_signal_lines"] = [
            f"{record.get('plugin_slug', 'plugin')} · {record.get('class_hint') or 'unclassified'} · "
            f"{record.get('file', '?')}:{record.get('line', '?')}"
            for record in recent_records[-4:]
        ]
        plugins = []
        p_rows = db.execute("SELECT slug,version,name,installs FROM completed ORDER BY completed_at DESC LIMIT 250").fetchall()
        for slug, version, name, installs in p_rows:
            plugins.append({"slug": slug, "version": version, "name": name or slug, "active_installs": installs or 0})
        decisions = recent_records
        alerts = [r for r in decisions if r.get("scope_decision", {}).get("decision") == "PASS"]
        report_state = dict(state, status=state["status"], scanned=total_plugins, signal_count=total_signals,
                            report_path=str(report_path), report_limit=250)
        report_state["log_path"] = str(log_path)
        report_state["handoff_path"] = str(handoff_path)
        live_log.event("INFO", "heartbeat", status=state["status"], plugins=total_plugins,
                       signals=total_signals, active=state["active"], queued=state["queued"])
        report_out = report_path.parent
        try:
            write_human_report(report_out, plugins, decisions, alerts, state["failures"],
                               state.get("semgrep_failures", 0), time.monotonic() - started,
                               stream_status=report_state, html_path=report_path, write_markdown=False)
            atomic_json(out / "phots-stream-status.json", report_state)
            write_memory_snapshot(out, db)
        except OSError as exc:
            state["last_output_error"] = str(exc)[:300]
            live_log.event("WARN", "report_write_failed", detail=exc)
        live_log.update_handoff(report_state)
        state.update(scanned=total_plugins, signal_count=total_signals)
        if args.tui:
            draw_phots_tui(state, recent_records)

    started = time.monotonic()
    active_futures = {}
    seen_this_session = set()
    retry_attempts = {}
    retry_after = {}
    pending = []
    last_error = None
    last_report_at = time.monotonic()
    last_console_heartbeat = time.monotonic()
    live_log.event("INFO", "stream_started", workers=workers, recommended=recommended,
                   free_ram_gib=available_gb, cpu_cores=os.cpu_count(),
                   feed=args.browse, search=search,
                   min_installs=args.min_installs, semgrep=semgrep_enabled,
                   ai_enabled=bool(ai_reviewer), ai_model=(ai_reviewer.config.model if ai_reviewer else None),
                   supabase=bool(store), report=report_path)
    publish()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers + 1) as pool:
            while True:
                # Discover a bounded batch; versions already persisted in SQLite are skipped on restart.
                discovered = []
                feed_used = selected_feed
                for page in range(1, args.pages_per_cycle + 1):
                    params = plugin_query_params(args.browse, page, args.per_page, search)
                    state["status"] = f"checking WordPress.org catalog page {page}/{args.pages_per_cycle}"
                    catalog_future = pool.submit(get_json, api_url(params))
                    try:
                        while True:
                            try:
                                data = catalog_future.result(timeout=1)
                                break
                            except concurrent.futures.TimeoutError:
                                drain_progress()
                                state["uptime"] = f"{int(time.monotonic() - started)}s"
                                if args.tui and key_pressed() == "q":
                                    raise KeyboardInterrupt
                                if args.tui:
                                    draw_phots_tui(state, [])
                                if time.monotonic() - last_report_at >= 15:
                                    publish()
                                    last_report_at = time.monotonic()
                                if not args.tui and time.monotonic() - last_console_heartbeat >= 30:
                                    print(f"Phots heartbeat · checking WordPress.org catalog page {page}", file=sys.stderr)
                                    last_console_heartbeat = time.monotonic()
                    except Exception as exc:
                        last_error = str(exc)[:300]
                        state["last_error"] = last_error
                        live_log.event("ERROR", "catalog_request_failed", feed=selected_feed,
                                       page=page, detail=last_error)
                        break
                    discovered.extend(data.get("plugins", []))
                    live_log.event("INFO", "catalog_page", feed=selected_feed, page=page,
                                   entries=len(data.get("plugins", [])))
                    if len(data.get("plugins", [])) < args.per_page:
                        break
                batch = []
                for p in discovered:
                    key = (p.get("slug"), str(p.get("version", "")))
                    if (not key[0] or not p.get("download_link") or key in seen_this_session
                            or int(p.get("active_installs", 0) or 0) < args.min_installs
                            or retry_after.get(key, 0) > time.monotonic()
                            or already_seen(*key)):
                        continue
                    seen_this_session.add(key)
                    batch.append(p)
                if not batch and args.browse != "popular" and not search:
                    feed_used = "popular"
                    state["status"] = f"no unseen eligible plugins in '{args.browse}' feed; checking popular feed"
                    state["scan_note"] = (f"The '{args.browse}' feed returned {len(discovered)} entries, but none met "
                                           f"the {args.min_installs}-install minimum and unseen-version checks. Falling back to popular.")
                    live_log.event("INFO", "feed_fallback", selected_feed=args.browse,
                                   fallback_feed="popular", entries=len(discovered),
                                   min_installs=args.min_installs)
                    publish()
                    discovered = []
                    for page in range(1, args.pages_per_cycle + 1):
                        params = plugin_query_params("popular", page, args.per_page)
                        state["status"] = f"fallback: checking popular catalog page {page}/{args.pages_per_cycle}"
                        catalog_future = pool.submit(get_json, api_url(params))
                        while True:
                            try:
                                data = catalog_future.result(timeout=1)
                                break
                            except concurrent.futures.TimeoutError:
                                state["uptime"] = f"{int(time.monotonic() - started)}s"
                                if args.tui:
                                    draw_phots_tui(state, [])
                                    if key_pressed() == "q":
                                        raise KeyboardInterrupt
                                if not args.tui and time.monotonic() - last_console_heartbeat >= 30:
                                    print(f"Phots heartbeat · checking popular catalog page {page}", file=sys.stderr)
                                    last_console_heartbeat = time.monotonic()
                        discovered.extend(data.get("plugins", []))
                        live_log.event("INFO", "catalog_page", feed="popular", page=page,
                                       entries=len(data.get("plugins", [])))
                        if len(data.get("plugins", [])) < args.per_page:
                            break
                    for p in discovered:
                        key = (p.get("slug"), str(p.get("version", "")))
                        if (not key[0] or not p.get("download_link") or key in seen_this_session
                                or int(p.get("active_installs", 0) or 0) < args.min_installs
                                or retry_after.get(key, 0) > time.monotonic()
                                or already_seen(*key)):
                            continue
                        seen_this_session.add(key)
                        batch.append(p)
                pending.extend(batch)
                state["status"] = "running"
                if pending:
                    queue = deque(pending)
                    pending.clear()
                    paused = False
                    def launch_available():
                        while not paused and queue and len(active_futures) < workers:
                            plugin_item = queue.popleft()
                            plugin_slug = plugin_item.get("slug", "plugin")
                            plugin_key = (plugin_slug, str(plugin_item.get("version", "")))
                            retry_attempts[plugin_key] = retry_attempts.get(plugin_key, 0) + 1
                            progress = lambda phase, detail, slug=plugin_slug: progress_events.put(
                                {"slug": slug, "phase": phase, "detail": detail})
                            job = pool.submit(download_and_scan, plugin_item, out / "source",
                                              args.max_files_per_plugin, args.max_findings_per_plugin,
                                              args.semgrep_timeout, args.semgrep_auto, progress,
                                              ai_reviewer, args.ai_max_findings_per_plugin,
                                              context_filter_enabled=args.context_filter,
                                              reviewed_clean=reviewed_clean)
                            active_futures[job] = plugin_item
                        state["queued"] = len(queue)
                    publish()
                    launch_available()
                    while active_futures or queue:
                        if active_futures:
                            done, _ = concurrent.futures.wait(active_futures, timeout=1,
                                                              return_when=concurrent.futures.FIRST_COMPLETED)
                        else:
                            done = set()
                            time.sleep(0.2)
                        drain_progress()
                        state["active"] = sum(not f.done() for f in active_futures)
                        state["queued"] = len(queue)
                        state["uptime"] = f"{int(time.monotonic() - started)}s"
                        key = key_pressed() if args.tui else None
                        if key in {"p", "r"}:
                            paused = not paused
                            state["status"] = "paused" if paused else "running"
                            publish()
                        elif key == "q":
                            raise KeyboardInterrupt
                        for future in done:
                            plugin = active_futures.pop(future)
                            drain_progress()
                            jobs.pop(plugin.get("slug"), None)
                            state["queued"] = len(active_futures)
                            try:
                                slug, found, cached, semgrep_status, source_hash, suppressed = future.result()
                                completed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
                                state["context_suppressed"] = state.get("context_suppressed", 0) + len(suppressed)
                                meta = {"slug": slug, "version": str(plugin["version"]),
                                        "name": str(plugin.get("name") or slug),
                                        "installs": int(plugin.get("active_installs", 0) or 0)}
                                save_plugin_completion(db, plugin, found, source_hash, completed_at)
                                try:
                                    write_memory_snapshot(out, db)
                                except OSError as exc:
                                    state["last_output_error"] = str(exc)[:300]
                                    live_log.event("WARN", "memory_snapshot_write_failed", plugin=slug,
                                                   detail=exc)
                                if store:
                                    try:
                                        store.upsert_catalog([plugin])
                                        store.save_signals(run_id, found)
                                    except Exception as exc:
                                        state["supabase_error"] = str(exc)[:300]
                                        live_log.event("ERROR", "supabase_write_failed", detail=exc)
                                if semgrep_status:
                                    state["semgrep_failures"] = state.get("semgrep_failures", 0) + 1
                                    state["last_semgrep_error"] = semgrep_status[:300]
                                    if state["semgrep_failures"] == 1:
                                        print(f"Semgrep issue: {semgrep_status}", file=sys.stderr)
                                    live_log.event("ERROR", "semgrep_failed", plugin=slug, detail=semgrep_status)
                                ai_summary = {}
                                for item in found:
                                    disposition = (item.get("ai_review") or {}).get("disposition")
                                    if disposition:
                                        ai_summary[disposition] = ai_summary.get(disposition, 0) + 1
                                ai_errors = [item["ai_review"].get("error") for item in found
                                             if (item.get("ai_review") or {}).get("error")]
                                if ai_errors:
                                    state["ai_errors"] = state.get("ai_errors", 0) + len(ai_errors)
                                    state["last_ai_error"] = str(ai_errors[-1])[:300]
                                    live_log.event("WARN", "ai_review_failed", plugin=slug,
                                                   count=len(ai_errors), detail=ai_errors[-1])
                                live_log.event("INFO", "plugin_completed", plugin=slug,
                                               version=plugin["version"], signals=len(found),
                                               cached=cached, ai=ai_summary)
                                publish(f"{slug} {plugin['version']}")
                            except Exception as exc:
                                state["failures"] += 1
                                state["last_error"] = f"{plugin.get('slug')}: {exc}"[:300]
                                live_log.event("ERROR", "plugin_failed", plugin=plugin.get("slug"),
                                               version=plugin.get("version"), detail=exc)
                                failed_key = (plugin.get("slug"), str(plugin.get("version", "")))
                                attempt = retry_attempts.get(failed_key, 1)
                                delay = retry_delay_seconds(attempt, exc)
                                if delay is not None:
                                    seen_this_session.discard(failed_key)
                                    retry_after[failed_key] = time.monotonic() + delay
                                    state["retry_note"] = f"Retrying {failed_key[0]} after {delay}s (attempt {attempt + 1}/3)."
                                    live_log.event("WARN", "plugin_retry_scheduled", plugin=failed_key[0],
                                                   attempt=attempt, delay_seconds=delay)
                                elif isinstance(exc, NonRetryableScanError):
                                    state["retry_note"] = (
                                        f"Not retrying {failed_key[0]} this run: {exc}. "
                                        "A later run can reconsider this version."
                                    )
                                    live_log.event("WARN", "plugin_retry_skipped", plugin=failed_key[0],
                                                   attempt=attempt, detail=exc)
                                else:
                                    state["retry_note"] = f"Stopped retrying {failed_key[0]} after 3 attempts; a restart will try again."
                                    live_log.event("ERROR", "plugin_retry_limit", plugin=failed_key[0], attempts=3)
                                publish(plugin.get("slug"))
                        launch_available()
                        if done or key:
                            publish()
                            last_report_at = time.monotonic()
                        elif args.tui:
                            draw_phots_tui(state, [])
                        if time.monotonic() - last_report_at >= 15:
                            publish()
                            last_report_at = time.monotonic()
                        if not args.tui and time.monotonic() - last_console_heartbeat >= 30:
                            summary = ", ".join(state.get("active_jobs", [])) or "workers idle"
                            print(f"Phots heartbeat · {state['scanned']} plugins · {state['signal_count']} signals · {summary}", file=sys.stderr)
                            last_console_heartbeat = time.monotonic()
                else:
                    state["status"] = "waiting for new plugin versions"
                    state["scan_note"] = (f"Checked {len(discovered)} entries in '{feed_used}'; no unseen versions "
                                           f"met the {args.min_installs}-install minimum. Next check in {args.poll_seconds}s.")
                    next_poll = time.monotonic() + args.poll_seconds
                    publish()
                    last_report_at = time.monotonic()
                    while time.monotonic() < next_poll:
                        time.sleep(min(1, max(0, next_poll - time.monotonic())))
                        if args.tui and key_pressed() == "q":
                            raise KeyboardInterrupt
                        seconds_left = max(0, int(next_poll - time.monotonic()))
                        state["status"] = f"waiting · next check in {seconds_left}s"
                        state["uptime"] = f"{int(time.monotonic() - started)}s"
                        if args.tui:
                            draw_phots_tui(state, [])
                        if time.monotonic() - last_report_at >= 15:
                            publish()
                            last_report_at = time.monotonic()
                        if not args.tui and time.monotonic() - last_console_heartbeat >= 30:
                            print(f"Phots heartbeat · waiting for new plugin versions ({seconds_left}s until next check)", file=sys.stderr)
                            last_console_heartbeat = time.monotonic()
                    state["status"] = "running"
    except KeyboardInterrupt:
        state["status"] = "stopped"
        live_log.event("INFO", "stream_stopped", plugins=state["scanned"], signals=state["signal_count"],
                       failures=state["failures"])
        publish()
        if store:
            finish_interrupted_stream_run(store, run_id, state, live_log)
            publish()
        print(f"\nPhots stopped cleanly. Live report: {report_path}")
    try:
        context_filter.save_reviewed_clean(reviewed_clean_path, reviewed_clean)
    except OSError:
        pass


def fetch_bytes(url: str, limit: int, timeout: int):
    for attempt in range(3):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json, application/zip"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.read(limit + 1)
        except urllib.error.HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise
        except urllib.error.URLError:
            if attempt == 2:
                raise
        time.sleep(0.75 * (2 ** attempt))


def get_json(url: str, timeout: int = 30):
    return json.loads(fetch_bytes(url, 10 * 1024 * 1024, timeout))


def api_url(params: dict[str, str]) -> str:
    return API + "?" + urllib.parse.urlencode(params)


def plugin_query_params(browse: str, page: int, per_page: int, search: str | None = None):
    params = {
        "action": "query_plugins",
        "request[per_page]": str(per_page),
        "request[page]": str(page),
        "request[fields][active_installs]": "1",
    }
    if search:
        params["request[search]"] = search
    else:
        params["request[browse]"] = browse
    return params


def feed_label(browse: str, search: str | None = None):
    return f"search: {search}" if search else browse


def catalog(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    plugins = []
    search = (getattr(args, "search", None) or "").strip() or None
    for page in range(1, args.pages + 1):
        params = plugin_query_params(args.browse, page, args.per_page, search)
        data = get_json(api_url(params))
        plugins.extend(data.get("plugins", []))
        print(f"Catalog page {page}: {len(data.get('plugins', []))} entries", file=sys.stderr)
        if len(data.get("plugins", [])) < args.per_page:
            break
        time.sleep(args.delay)
    # API install counts are rounded. Keep the threshold strict and store the observed value.
    eligible = [p for p in plugins if int(p.get("active_installs", 0) or 0) >= args.min_installs
                and p.get("slug") and p.get("version") and p.get("download_link")]
    (out / "catalog.json").write_text(json.dumps(eligible, indent=2), encoding="utf-8")
    if args.supabase:
        store = SupabaseStore()
        store.verify()
        store.upsert_catalog(eligible)
    print(f"Saved {len(eligible)} plugins above the install threshold from "
          f"'{feed_label(args.browse, search)}' to {out / 'catalog.json'}")


AUDIT_MANIFESTS = {
    "composer.json": ("composer", "manifest"),
    "composer.lock": ("composer", "lockfile"),
    "package.json": ("npm", "manifest"),
    "package-lock.json": ("npm", "lockfile"),
    "npm-shrinkwrap.json": ("npm", "lockfile"),
}
AUDIT_IGNORED_DIRS = {
    ".git", ".next", ".pytest_cache", ".tox", ".venv", "__pycache__",
    "build", "coverage", "dist", "node_modules", "output", "target",
    "vendor", "venv",
}
LOCAL_AUDIT_SOURCE_EXTENSIONS = SOURCE_EXTENSIONS | {
    ".bash", ".cjs", ".conf", ".html", ".ini", ".js", ".jsx", ".json",
    ".mjs", ".ps1", ".sh", ".toml", ".ts", ".tsx", ".xml", ".yaml", ".yml",
}
LOCAL_AUDIT_PATTERNS = [
    ("entrypoint", "rest_route", re.compile(r"\bregister_rest_route\s*\(", re.I)),
    ("entrypoint", "ajax_handler", re.compile(r"\badd_action\s*\(\s*['\"]wp_ajax_(?:nopriv_)?[a-z0-9_]+", re.I)),
    ("entrypoint", "admin_page", re.compile(r"\badd_(?:menu_page|submenu_page|options_page|theme_page)\s*\(", re.I)),
    ("entrypoint", "shortcode", re.compile(r"\badd_shortcode\s*\(", re.I)),
    ("input", "request_source", re.compile(
        r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|->get_(?:param|json_params)\s*\(", re.I)),
    ("authorization", "capability_check", re.compile(r"\bcurrent_user_can\s*\(", re.I)),
    ("csrf", "nonce_check", re.compile(
        r"\b(?:check_ajax_referer|check_admin_referer|wp_verify_nonce)\s*\(", re.I)),
    ("database", "wpdb_access", re.compile(r"\$wpdb\s*->\s*(?:query|get_row|get_results|get_var|insert|update|delete)\s*\(", re.I)),
    ("output", "output_operation", re.compile(r"\b(?:echo|print|printf)\b", re.I)),
    ("upload", "upload_operation", re.compile(
        r"\b(?:move_uploaded_file|wp_handle_upload|wp_handle_sideload|wp_upload_bits)\s*\(", re.I)),
    ("filesystem", "file_operation", re.compile(
        r"\b(?:file_get_contents|file_put_contents|fopen|readfile|unlink|rename|copy|rmdir)\s*\(", re.I)),
    ("deserialization", "deserialize_operation", re.compile(r"\bunserialize\s*\(", re.I)),
    ("execution", "dynamic_execution", re.compile(
        r"\b(?:eval|exec|shell_exec|system|passthru|proc_open|popen)\s*\(", re.I)),
    ("workflow", "state_change", re.compile(
        r"\b(?:update_option|delete_option|wp_delete_post|delete_user_meta|wp_insert_user|wp_update_user)\s*\(", re.I)),
]
LOCAL_SECRET_PATTERN = re.compile(
    r"""(?i)(?:^|[^A-Za-z0-9])"""
    r"""(?:api[_-]?(?:key|token)|access[_-]?token|client[_-]?secret|password|secret|token|private[_-]?key)"""
    r"""[^=:\r\n]{0,32}(?:=>|=|:)\s*"""
    r"""(?:['"](?P<quoted_value>[^'"\r\n]{8,})['"]|(?P<plain_value>[^#\s'"]{8,}))"""
)
LOCAL_SECRET_PLACEHOLDERS = (
    "changeme", "change-me", "example", "dummy", "placeholder",
    "your-", "your_", "xxxx", "12345678", "test",
)
LOCAL_AUDIT_MAX_FILES = 20000
LOCAL_AUDIT_MAX_INVENTORY_FILES = 50000
LOCAL_AUDIT_MAX_TOTAL_BYTES = 512 * 1024 * 1024
LOCAL_AUDIT_OUTPUT_LIMIT = 20 * 1024 * 1024


def discover_dependency_manifests(root: Path, out: Path):
    """Inventory Composer/npm manifests without descending into dependency trees."""
    manifests = []
    root = root.resolve()
    out = out.resolve()
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current).resolve()
        directories[:] = sorted(
            name for name in directories
            if name.lower() not in AUDIT_IGNORED_DIRS
            and not (
                root in out.parents
                and ((current_path / name).resolve() == out
                     or out in (current_path / name).resolve().parents)
            )
        )
        for filename in sorted(filenames):
            entry = AUDIT_MANIFESTS.get(filename.lower())
            if entry is None:
                continue
            path = Path(current) / filename
            manifests.append({
                "path": path.relative_to(root).as_posix(),
                "directory": path.parent.relative_to(root).as_posix(),
                "ecosystem": entry[0],
                "kind": entry[1],
                "size_bytes": path.stat().st_size,
            })
    manifests.sort(key=lambda item: (item["path"].casefold(), item["path"]))
    return manifests


def audit_command(executable: str, arguments: list[str]):
    command = [executable, *arguments]
    if os.name == "nt" and Path(executable).suffix.lower() in {".bat", ".cmd"}:
        command_line = subprocess.list2cmdline(command)
        return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c",
                f'"{command_line}"']
    return command


def run_dependency_audits(root: Path, out: Path, timeout: int):
    manifests = discover_dependency_manifests(root, out)
    ecosystems = {
        ecosystem: {
            entry["directory"] for entry in manifests
            if entry["ecosystem"] == ecosystem and entry["kind"] == "lockfile"
        }
        for ecosystem in ("composer", "npm")
    }
    manifest_directories = {
        (entry["ecosystem"], entry["directory"])
        for entry in manifests if entry["kind"] == "manifest"
    }
    targets = {
        ecosystem: sorted(
            directory for directory in directories
            if (ecosystem, directory) in manifest_directories
        )
        for ecosystem, directories in ecosystems.items()
    }
    executables = {name: shutil.which(name) for name in ("composer", "npm")}
    results = []
    output_dir = out / "audit" / "tool-output"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_index = 0

    for ecosystem in ("composer", "npm"):
        for directory in targets[ecosystem]:
            executable = executables[ecosystem]
            result = {
                "ecosystem": ecosystem,
                "directory": directory or ".",
                "status": "not_installed" if executable is None else "pending",
            }
            if executable is None:
                results.append(result)
                continue

            arguments = (["audit", "--format=json", "--no-interaction", "--no-plugins"]
                         if ecosystem == "composer" else ["audit", "--json"])
            result["command"] = [ecosystem, *arguments]
            try:
                completed = subprocess.run(
                    audit_command(executable, arguments),
                    cwd=root / directory,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                )
                stdout = completed.stdout or ""
                stderr = completed.stderr or ""
                result["exit_code"] = completed.returncode
                result["status"] = "completed" if completed.returncode == 0 else "nonzero_exit"
                if stderr:
                    result["stderr"] = stderr[-4000:]
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout or ""
                stderr = exc.stderr or ""
                if isinstance(stdout, bytes):
                    stdout = stdout.decode("utf-8", errors="replace")
                if isinstance(stderr, bytes):
                    stderr = stderr.decode("utf-8", errors="replace")
                result["status"] = "timed_out"
                result["error"] = f"Audit exceeded the {timeout}s timeout."
                if stderr:
                    result["stderr"] = stderr[-4000:]
            except OSError as exc:
                stdout = ""
                result["status"] = "failed"
                result["error"] = str(exc)[:1000]

            if stdout:
                output_index += 1
                try:
                    json.loads(stdout)
                    suffix = ".json"
                except json.JSONDecodeError:
                    suffix = ".txt"
                output_path = output_dir / f"{ecosystem}-{output_index:03d}{suffix}"
                output_path.write_text(stdout, encoding="utf-8")
                result["output"] = output_path.relative_to(out).as_posix()
            results.append(result)

    return manifests, executables, results


def dependency_audit(args):
    root = Path(args.root).resolve()
    out = Path(args.out).resolve()
    if not root.is_dir():
        raise ValueError(f"Audit root is not a directory: {root}")
    if out == root:
        raise ValueError("Audit output directory must be separate from the audit root.")
    out.mkdir(parents=True, exist_ok=True)
    manifests, executables, results = run_dependency_audits(root, out, args.timeout)
    summary = {
        "scan_type": "local_dependency_audit",
        "root": str(root),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "network_note": "Composer and npm audit may contact configured package registries.",
        "tools": {name: bool(path) for name, path in executables.items()},
        "manifests": manifests,
        "audits": results,
    }
    json_path = out / "audit" / "dependency-audit.json"
    markdown_path = out / "audit" / "dependency-audit.md"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(json_path, summary)

    lines = [
        "# Local Composer/npm Dependency Audit",
        "",
        f"- Root: `{root}`",
        "- This command inventories manifests and runs installed dependency-audit tools only.",
        "- It does not install dependencies or execute plugin code.",
        "- Composer/npm audit may contact configured package registries.",
        "",
        "## Manifest inventory",
        "",
    ]
    if manifests:
        for item in manifests:
            lines.append(f"- `{item['path']}` — {item['ecosystem']} {item['kind']} ({item['size_bytes']} bytes)")
    else:
        lines.append("No Composer or npm manifests/lockfiles were found.")
    lines.extend(["", "## Audit runs", ""])
    if results:
        for item in results:
            lines.append(f"- **{item['ecosystem']}** in `{item['directory']}`: `{item['status']}`"
                         + (f" (exit {item['exit_code']})" if "exit_code" in item else "")
                         + (f" — output: `{item['output']}`" if item.get("output") else "")
                         + (f" — {item['error']}" if item.get("error") else ""))
    else:
        lines.append("No matching manifest+lockfile pairs were available to audit.")
    lines.extend([
        "",
        "A nonzero exit can indicate reported vulnerabilities or a tool/registry error; inspect the saved output and stderr before drawing conclusions.",
    ])
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Dependency audit complete: {len(manifests)} manifests/lockfiles, "
          f"{len(results)} audit target(s). Report: {markdown_path}")


def inventory_local_project(root: Path, out: Path):
    """Collect bounded source-surface review locations without retaining code snippets."""
    root = root.resolve()
    out = out.resolve()
    extensions = {}
    file_paths = []
    file_count = 0
    file_inventory_truncated = False
    source_files = []
    targets = []
    warnings = []
    scanned = 0
    scanned_bytes = 0
    truncation_reason = None

    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current).resolve()
        directories[:] = sorted(
            name for name in directories
            if name.lower() not in AUDIT_IGNORED_DIRS
            and not (current_path / name).is_symlink()
            and (current_path / name).resolve() != out
            and out not in (current_path / name).resolve().parents
        )
        for filename in sorted(filenames):
            path = Path(current) / filename
            if path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            file_count += 1
            if len(file_paths) < LOCAL_AUDIT_MAX_INVENTORY_FILES:
                file_paths.append(relative)
            else:
                file_inventory_truncated = True
            extension = path.suffix.lower()
            if (
                extension not in LOCAL_AUDIT_SOURCE_EXTENSIONS and filename.lower() != ".env"
            ):
                continue
            if scanned >= LOCAL_AUDIT_MAX_FILES:
                truncation_reason = f"source inventory stopped at {LOCAL_AUDIT_MAX_FILES} files"
                break
            scanned += 1
            extension_key = extension or "<dotfile>"
            extensions[extension_key] = extensions.get(extension_key, 0) + 1
            source_files.append(relative)
            try:
                file_size = path.stat().st_size
                if file_size > MAX_FILE_BYTES:
                    warnings.append({"path": relative, "reason": "file exceeds the 2 MiB scan limit"})
                    continue
                if scanned_bytes + file_size > LOCAL_AUDIT_MAX_TOTAL_BYTES:
                    truncation_reason = (
                        f"source inventory stopped at the "
                        f"{LOCAL_AUDIT_MAX_TOTAL_BYTES // 1024**2} MiB byte limit"
                    )
                    break
                scanned_bytes += file_size
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                warnings.append({"path": relative, "reason": f"could not read file: {exc}"})
                continue

            for line_number, line in enumerate(text.splitlines(), start=1):
                for category, kind, pattern in LOCAL_AUDIT_PATTERNS:
                    if pattern.search(line):
                        targets.append({
                            "path": relative,
                            "line": line_number,
                            "category": category,
                            "kind": kind,
                        })
                secret_match = LOCAL_SECRET_PATTERN.search(line)
                if secret_match:
                    value = (secret_match.group("quoted_value")
                             or secret_match.group("plain_value")).strip()
                    lowered = value.casefold()
                    if not any(marker in lowered for marker in LOCAL_SECRET_PLACEHOLDERS):
                        targets.append({
                            "path": relative,
                            "line": line_number,
                            "category": "secrets",
                            "kind": "hardcoded_secret_candidate",
                        })
        if truncation_reason:
            break

    targets.sort(key=lambda item: (item["path"].casefold(), item["line"], item["category"], item["kind"]))
    if truncation_reason:
        warnings.append({"reason": truncation_reason})
    if file_inventory_truncated:
        warnings.append({
            "reason": f"file inventory stopped at {LOCAL_AUDIT_MAX_INVENTORY_FILES} paths",
        })
    category_counts = {}
    for target in targets:
        category_counts[target["category"]] = category_counts.get(target["category"], 0) + 1
    return {
        "file_count": file_count,
        "file_inventory_truncated": file_inventory_truncated,
        "files": file_paths,
        "source_file_count": len(source_files),
        "files_by_extension": dict(sorted(extensions.items())),
        "review_target_count": len(targets),
        "review_targets": targets,
        "category_counts": category_counts,
        "warnings": warnings,
        "truncated": truncation_reason is not None,
    }, source_files


def _audit_output_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def run_local_audit_tool(name: str, executable: str, arguments: list[str], root: Path,
                         report_root: Path, output_path: Path, timeout: int,
                         env=None, acceptable_exit_codes=(0,)):
    """Run one explicitly selected local tool and persist bounded output."""
    result = {
        "tool": name,
        "status": "pending",
        "command": [name, *arguments],
    }
    try:
        completed = subprocess.run(
            audit_command(executable, arguments),
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            env=env,
            check=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        result["exit_code"] = completed.returncode
        result["status"] = "completed" if completed.returncode in acceptable_exit_codes else "nonzero_exit"
    except subprocess.TimeoutExpired as exc:
        stdout = _audit_output_text(exc.stdout)
        stderr = _audit_output_text(exc.stderr)
        result["status"] = "timed_out"
        result["error"] = f"Tool exceeded the {timeout}s timeout."
    except OSError as exc:
        stdout = ""
        stderr = ""
        result["status"] = "failed"
        result["error"] = str(exc)[:1000]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if stdout:
        clipped = stdout[:LOCAL_AUDIT_OUTPUT_LIMIT]
        output_path.write_text(clipped, encoding="utf-8")
        result["output"] = output_path.relative_to(report_root).as_posix()
        if len(stdout) > len(clipped):
            result["output_truncated"] = True
    if stderr:
        stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.txt")
        clipped_stderr = stderr[:LOCAL_AUDIT_OUTPUT_LIMIT]
        stderr_path.write_text(clipped_stderr, encoding="utf-8")
        result["stderr_output"] = stderr_path.relative_to(report_root).as_posix()
        result["stderr"] = stderr[-4000:]
        if len(stderr) > len(clipped_stderr):
            result["stderr_truncated"] = True
    return result


def local_tool_path(name: str, root: Path):
    executable = shutil.which(name)
    if executable:
        return executable
    suffixes = (".bat", ".cmd", ".exe", "") if os.name == "nt" else ("",)
    for directory in (root / "vendor" / "bin", root / "node_modules" / ".bin"):
        for suffix in suffixes:
            candidate = directory / f"{name}{suffix}"
            if candidate.is_file():
                return str(candidate)
    return None


def local_security_audit(args):
    root = Path(args.root).resolve()
    out = Path(args.out).resolve()
    if not root.is_dir():
        raise ValueError(f"Audit root is not a directory: {root}")
    if out == root:
        raise ValueError("Audit output directory must be separate from the audit root.")
    report_root = out / "audit"
    tool_output = report_root / "tool-output"
    tool_output.mkdir(parents=True, exist_ok=True)

    inventory, source_files = inventory_local_project(root, out)
    file_paths = inventory.pop("files")
    inventory_path = report_root / "surface-inventory.json"
    atomic_json(inventory_path, inventory)
    file_inventory_path = report_root / "file-inventory.txt"
    file_inventory_path.write_text(
        "".join(path + "\n" for path in file_paths),
        encoding="utf-8",
    )
    tool_results = []

    semgrep = shutil.which("semgrep")
    if semgrep:
        command = [
            "scan", "--config", str(LOCAL_RULES), "--json", "--metrics=off", "--quiet",
            "-j", "1", "--max-target-bytes", str(MAX_FILE_BYTES),
        ]
        for directory in sorted(AUDIT_IGNORED_DIRS):
            command.extend(["--exclude", f"**/{directory}/**"])
        if out == root or root in out.parents:
            command.extend(["--exclude", out.relative_to(root).as_posix() + "/**"])
        command.append(str(root))
        semgrep_env = dict(os.environ)
        semgrep_env["SEMGREP_SEND_METRICS"] = "off"
        semgrep_env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        semgrep_result = run_local_audit_tool(
            "semgrep", semgrep, command, root, out,
            tool_output / "semgrep.json", args.timeout, env=semgrep_env,
            acceptable_exit_codes=(0, 1),
        )
        semgrep_path = out / semgrep_result["output"] if semgrep_result.get("output") else None
        if semgrep_path:
            try:
                semgrep_report = json.loads(semgrep_path.read_text(encoding="utf-8"))
                semgrep_result["finding_count"] = len(semgrep_report.get("results", []))
                semgrep_result["analysis_errors"] = [
                    str(item.get("message", item))[:250]
                    for item in semgrep_report.get("errors", [])[:10]
                ]
                if semgrep_result["analysis_errors"]:
                    semgrep_result["status"] = "completed_with_analysis_errors"
            except (OSError, json.JSONDecodeError) as exc:
                semgrep_result["status"] = "invalid_output"
                semgrep_result["error"] = str(exc)[:1000]
        tool_results.append(semgrep_result)
    else:
        tool_results.append({"tool": "semgrep", "status": "not_installed"})

    manifests = discover_dependency_manifests(root, out)
    if args.include_dependencies:
        manifests, executables, dependency_results = run_dependency_audits(root, out, args.timeout)
        tool_results.extend(dependency_results)
    else:
        tool_results.append({"tool": "composer/npm audit", "status": "disabled_by_option"})

    php_present = any(Path(path).suffix.lower() == ".php" for path in source_files)
    js_present = any(Path(path).suffix.lower() in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
                     for path in source_files)

    if not args.run_project_tools:
        for name in ("phpcs", "phpstan", "psalm"):
            tool_results.append({
                "tool": name,
                "status": "opt_in_required",
                "note": "Use --run-project-tools only for code and tool configuration you trust.",
            })
    elif php_present:
        phpcs = local_tool_path("phpcs", root)
        if not phpcs:
            tool_results.append({"tool": "phpcs", "status": "not_installed"})
        else:
            standards_result = run_local_audit_tool(
                "phpcs", phpcs, ["-i"], root, out,
                tool_output / "phpcs-standards.txt", args.timeout,
            )
            tool_results.append(standards_result)
            standards_path = out / standards_result["output"] if standards_result.get("output") else None
            standards_text = standards_path.read_text(encoding="utf-8", errors="replace") if standards_path else ""
            installed_standards = set(re.findall(r"[A-Za-z0-9_]+", standards_text))
            for standard in ("WordPressVIPMinimum", "WordPress"):
                if standard in installed_standards:
                    tool_results.append(run_local_audit_tool(
                        f"phpcs-{standard}", phpcs,
                        ["--standard=" + standard, "--report=json", str(root)],
                        root, out, tool_output / f"phpcs-{standard}.json", args.timeout,
                    ))
                else:
                    tool_results.append({
                        "tool": f"phpcs-{standard}",
                        "status": "standard_not_installed",
                    })

        for name, config_names, command in (
            ("phpstan", ("phpstan.neon", "phpstan.neon.dist"),
             ["analyse", "--no-progress", "--error-format=json"]),
            ("psalm", ("psalm.xml", "psalm.xml.dist"),
             ["--taint-analysis", "--output-format=json"]),
        ):
            executable = local_tool_path(name, root)
            config = next((root / filename for filename in config_names if (root / filename).is_file()), None)
            if not executable:
                tool_results.append({"tool": name, "status": "not_installed"})
            elif config is None:
                tool_results.append({"tool": name, "status": "skipped_no_project_config"})
            else:
                tool_results.append(run_local_audit_tool(
                    name, executable, command, root, out,
                    tool_output / f"{name}.json", args.timeout,
                ))
    elif args.run_project_tools:
        for name in ("phpcs", "phpstan", "psalm"):
            tool_results.append({"tool": name, "status": "not_applicable_no_php"})

    if js_present:
        retire = local_tool_path("retire", root)
        if retire:
            tool_results.append(run_local_audit_tool(
                "retire", retire, ["--path", str(root), "--outputformat", "json"],
                root, out, tool_output / "retire.json", args.timeout,
            ))
        else:
            tool_results.append({"tool": "retire", "status": "not_installed"})

    gitleaks = shutil.which("gitleaks")
    if gitleaks:
        redacted_report = tool_output / "gitleaks-redacted.json"
        result = run_local_audit_tool(
            "gitleaks", gitleaks,
            ["dir", "--redact", "--report-format", "json", "--report-path",
             str(redacted_report), str(root)],
            root, out, tool_output / "gitleaks.log", args.timeout,
        )
        if redacted_report.is_file():
            result["report"] = redacted_report.relative_to(out).as_posix()
        result["redacted"] = True
        tool_results.append(result)
    else:
        tool_results.append({"tool": "gitleaks", "status": "not_installed"})

    syft = shutil.which("syft")
    sbom_path = tool_output / "sbom.cyclonedx.json"
    if syft:
        result = run_local_audit_tool(
            "syft", syft, ["dir:" + str(root), "-o", "cyclonedx-json"],
            root, out, sbom_path, args.timeout,
        )
        if result.get("status") == "completed" and sbom_path.is_file():
            result["sbom_components"] = None
            try:
                sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
                result["sbom_components"] = len(sbom.get("components", []))
            except (OSError, json.JSONDecodeError):
                result["status"] = "invalid_output"
        tool_results.append(result)
    else:
        tool_results.append({"tool": "syft", "status": "not_installed"})

    grype = shutil.which("grype")
    if grype and sbom_path.is_file():
        grype_env = dict(os.environ)
        grype_env["GRYPE_DB_AUTO_UPDATE"] = "false"
        tool_results.append(run_local_audit_tool(
            "grype", grype, ["sbom:" + str(sbom_path), "-o", "json",
                             "--check-for-app-update=false"],
            root, out, tool_output / "grype.json", args.timeout, env=grype_env,
        ))
    else:
        tool_results.append({
            "tool": "grype",
            "status": "not_installed" if not grype else "skipped_no_syft_sbom",
            "note": "Grype is not allowed to download or update its vulnerability database during this audit.",
        })

    trivy = shutil.which("trivy")
    if trivy:
        trivy_result = run_local_audit_tool(
            "trivy", trivy,
            ["fs", "--skip-db-update", "--skip-java-db-update", "--format", "json",
             "--output", str(tool_output / "trivy.json"), str(root)],
            root, out, tool_output / "trivy.log", args.timeout,
        )
        trivy_report = tool_output / "trivy.json"
        if trivy_report.is_file():
            trivy_result["report"] = trivy_report.relative_to(out).as_posix()
        tool_results.append(trivy_result)
    else:
        tool_results.append({"tool": "trivy", "status": "not_installed"})

    tool_results.append({
        "tool": "codeql",
        "status": "manual_setup_required",
        "note": "Database creation and query-pack setup are intentionally not run automatically.",
    })
    summary = {
        "scan_type": "local_wordpress_security_audit",
        "root": str(root),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope": "Local source inventory and installed static/dependency tools; plugin code is not executed.",
        "network_note": (
            "Composer/npm audit may contact configured registries. Semgrep uses only bundled local rules; "
            "Grype/Trivy database updates are disabled."
        ),
        "inventory": inventory,
        "inventory_report": inventory_path.relative_to(out).as_posix(),
        "file_inventory_report": file_inventory_path.relative_to(out).as_posix(),
        "dependency_manifests": manifests,
        "tools": tool_results,
        "manual_review": [
            "Trace each REST/AJAX/admin handler to its authorization and object-ownership checks.",
            "Verify every state-changing request has a correctly scoped nonce; a nonce is not authorization.",
            "Trace request sources through validation to SQL, output, file, upload, deserialization, and execution sinks.",
            "Review settings, role changes, import/export, and multi-step workflows for required preconditions and replay/race issues.",
            "Exercise only an authorized local WordPress instance; dynamic testing is not performed by this command.",
        ],
    }
    json_path = report_root / "security-audit.json"
    markdown_path = report_root / "security-audit.md"
    atomic_json(json_path, summary)
    lines = [
        "# Local WordPress Security Audit",
        "",
        f"- Root: `{root}`",
        f"- Source files inventoried: {inventory['source_file_count']}",
        f"- Review locations: {inventory['review_target_count']}",
        "- This is a static triage workflow, not a vulnerability verdict.",
        "- Phots does not execute plugin code or perform live-site testing.",
        "- Composer/npm audits may contact configured package registries.",
        "",
        "## Source surfaces for manual review",
        "",
        f"Inventory JSON: `{summary['inventory_report']}`",
        f"File list: `{summary['file_inventory_report']}` ({inventory['file_count']} file(s)"
        + ("; truncated" if inventory["file_inventory_truncated"] else "") + ")",
    ]
    for category, count in sorted(inventory["category_counts"].items()):
        lines.append(f"- **{category}:** {count} location(s)")
    if inventory["review_targets"]:
        lines.extend(["", "### Location index", ""])
        for target in inventory["review_targets"][:200]:
            lines.append(
                f"- `{target['path']}:{target['line']}` — {target['category']} / {target['kind']}"
            )
        if len(inventory["review_targets"]) > 200:
            lines.append("- Additional locations are listed in `surface-inventory.json`.")
    for warning in inventory["warnings"]:
        lines.append(f"- **Inventory warning:** {warning.get('path', '')} {warning['reason']}")
    lines.extend(["", "## Dependency manifests", ""])
    if manifests:
        lines.extend(
            f"- `{item['path']}` — {item['ecosystem']} {item['kind']}"
            for item in manifests
        )
    else:
        lines.append("No Composer/npm manifests or lockfiles were found.")
    lines.extend(["", "## Tool results", ""])
    for result in tool_results:
        lines.append(
            f"- **{result['tool']}**: `{result['status']}`"
            + (f" (exit {result['exit_code']})" if "exit_code" in result else "")
            + (f" — output: `{result['output']}`" if result.get("output") else "")
            + (f" — {result['note']}" if result.get("note") else "")
            + (f" — {result['error']}" if result.get("error") else "")
        )
    lines.extend(["", "## Manual review and validation", ""])
    lines.extend(f"- {item}" for item in summary["manual_review"])
    lines.extend([
        "",
        "Use an exit status or a rule match as a prompt to inspect the saved output; neither proves exploitability. "
        "Missing capability/nonce checks and business-logic defects require handler-level review.",
    ])
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Local security audit complete. Report: {markdown_path}")


def download_one(plugin, root: Path, progress=None):
    slug = plugin["slug"]
    version = str(plugin["version"])
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", slug) or slug in {".", ".."}:
        raise NonRetryableScanError("plugin slug contains unsupported path characters")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", version) or version in {".", ".."}:
        raise NonRetryableScanError("plugin version contains unsupported path characters")
    package_url = urllib.parse.urlparse(plugin["download_link"])
    if package_url.scheme != "https" or package_url.hostname != "downloads.wordpress.org":
        raise NonRetryableScanError("package URL is not an HTTPS WordPress.org download")
    target = root / slug / version
    root_resolved = root.resolve()
    if root_resolved not in target.resolve().parents:
        raise NonRetryableScanError("source cache path resolves outside the configured source directory")
    marker = target / ".complete"
    had_cache_marker = marker.exists() or marker.is_symlink()
    if marker.is_file() and not marker.is_symlink():
        saved = {}
        try:
            loaded = json.loads(marker.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                saved = loaded
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            pass
        saved_verification = saved.get("verification")
        if (saved.get("fetcher_version") == wp_fetcher.__version__
                and saved.get("version_api") == version
                and isinstance(saved_verification, dict)):
            if progress:
                progress("source cache", "reusing verified download")
            return slug, version, target, True, saved_verification
    if target.is_symlink():
        target.unlink()
    elif target.is_dir():
        shutil.rmtree(target)
    elif target.exists():
        target.unlink()
    if had_cache_marker:
        if progress:
            progress("source cache", "refreshing an unverified legacy cache")
    if progress:
        progress("downloading ZIP", "resumable transfer from downloads.wordpress.org")
    archive_path = root / ".downloads" / slug / f"{version}.zip"
    archive_parent = archive_path.parent.resolve()
    if root_resolved not in archive_parent.parents:
        raise NonRetryableScanError("download cache path resolves outside the configured source directory")
    if archive_path.is_symlink() or (archive_path.exists() and not archive_path.is_file()):
        raise NonRetryableScanError("download cache entry is not a regular file")
    fetch_config = wp_fetcher.FetcherConfig(
        staging=root,
        retries=2,
        timeout_secs=60,
        max_download_mb=MAX_ZIP_BYTES // (1024 * 1024),
        max_uncompressed_mb=500,
    )
    try:
        _, archive_bytes = wp_fetcher.download_plugin(
            plugin["download_link"], archive_path, fetch_config)
    except wp_fetcher.FetcherPolicyError as exc:
        raise NonRetryableScanError(str(exc)) from exc
    if progress:
        progress("verifying archive", f"received {archive_bytes / 1024 / 1024:.1f} MiB; checking ZIP integrity and version")
    verification = wp_fetcher.verify_plugin_version(archive_path, version)
    if verification.get("error"):
        raise NonRetryableScanError(verification["error"])
    if verification.get("drift") and progress:
        progress(
            "version drift",
            f"API reports {version}; archive reports {verification['version_verified']} "
            f"({verification['version_source']}); findings will use the archive version",
        )
    if progress:
        progress("extracting source", f"expanded-size cap: {fetch_config.max_uncompressed_mb} MiB")
    try:
        file_count = wp_fetcher.extract_plugin_zip(archive_path, target, fetch_config)
    except wp_fetcher.FetcherPolicyError as exc:
        raise NonRetryableScanError(str(exc)) from exc
    marker.write_text(json.dumps({
        "fetcher_version": wp_fetcher.__version__,
        "version_api": version,
        "verification": verification,
        "zip_sha256": wp_fetcher.sha256_file(archive_path),
        "archive_bytes": archive_bytes,
        "files_count": file_count,
    }, indent=2), encoding="utf-8")
    archive_path.unlink(missing_ok=True)
    if progress:
        progress("source ready", f"archive safely extracted ({file_count} files)")
    return slug, version, target, False, verification


def scan_tree(slug: str, version: str, root: Path, max_files: int, max_findings: int, progress=None):
    findings = []
    candidates = (p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SOURCE_EXTENSIONS)
    # Pick a deterministic, bounded subset so repeated scans cover the same paths.
    paths = heapq.nsmallest(max_files, candidates, key=lambda p: p.as_posix().casefold())
    for path_index, path in enumerate(paths, 1):
        if progress and (path_index == 1 or path_index % 25 == 0 or path_index == len(paths)):
            progress("source pattern scan", f"file {path_index}/{len(paths)}: {path.name}")
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        newlines = [match.start() for match in re.finditer("\n", source)]
        lines = source.splitlines()
        language = path.suffix.lower().lstrip(".")
        language_rules = RULES if language == "php" else FALLBACK_RULES.get(language, [])
        for rule_id, pattern, note, class_hint in language_rules:
            for match in pattern.finditer(source):
                line = bisect.bisect_left(newlines, match.start()) + 1
                relative = str(path.relative_to(root))
                excerpt = " ".join(lines[max(0, line - 2):min(len(lines), line + 1)]).strip()
                excerpt = excerpt[:360]
                match_key = re.sub(r"\s+", " ", match.group(0)).strip().lower()
                signal_id = hashlib.sha256(f"{slug}|{version}|{relative}|{line}|{rule_id}|{match_key}".encode()).hexdigest()[:20]
                findings.append({"signal_id": signal_id, "plugin_slug": slug, "version": version,
                                 "file": relative,
                                 "line": line, "rule": rule_id, "signal": note,
                                 "excerpt": excerpt, "class_hint": class_hint,
                                 "confidence": "low", "language": language,
                                 "engine": "heuristic",
                                 "review_status": "unreviewed"})
                if len(findings) >= max_findings:
                    return findings
    return findings


FALLBACK_RULES = {
    "py": [
        ("python-sql-direct", re.compile(r"\b(?:execute|executemany)\s*\([^)]{0,300}(?:request\.(?:args|form|values|GET|POST)|input\s*\()", re.I | re.S), "Request-derived value appears near a SQL execution call; inspect parameter binding.", "sql_injection"),
        ("python-command-direct", re.compile(r"\b(?:os\.system|subprocess\.(?:run|Popen|call|check_output))\s*\([^)]{0,300}(?:request\.(?:args|form|values|GET|POST)|input\s*\()", re.I | re.S), "Request-derived value appears near a process execution call; verify shell use and impact.", "remote_code_execution"),
        ("python-pickle-input", re.compile(r"\b(?:pickle|_pickle)\.loads?\s*\([^)]{0,250}(?:request\.|input\s*\()", re.I | re.S), "Request-derived data appears near unsafe deserialization; verify whether it enables code execution.", "remote_code_execution"),
    ],
    "go": [
        ("go-sql-direct", re.compile(r"\.(?:Query|QueryRow|Exec|QueryContext|ExecContext)\s*\([^)]{0,350}(?:FormValue\s*\(|URL\.Query\s*\(|fmt\.Sprintf\s*\()", re.I | re.S), "Request data or formatted SQL appears near a database execution call.", "sql_injection"),
        ("go-shell-direct", re.compile(r"exec\.Command(?:Context)?\s*\([^)]{0,350}(?:FormValue\s*\(|URL\.Query\s*\(|fmt\.Sprintf\s*\()", re.I | re.S), "Request-derived value appears near process execution; inspect for shell invocation.", "remote_code_execution"),
        ("go-file-path-direct", re.compile(r"\b(?:os\.(?:Open|ReadFile|Remove|RemoveAll)|ioutil\.ReadFile)\s*\([^)]{0,350}(?:FormValue\s*\(|URL\.Query\s*\()", re.I | re.S), "Request-derived value appears near a filesystem path operation.", "directory_traversal"),
    ],
    "rs": [
        ("rust-sql-dynamic", re.compile(r"(?:sqlx::query|diesel::sql_query)\s*\([^)]{0,350}(?:format!\s*\(|query_string\s*\(|std::env::args)", re.I | re.S), "Dynamic or request-derived SQL appears near a raw query API.", "sql_injection"),
        ("rust-shell-direct", re.compile(r"Command::new\s*\([^)]{0,250}(?:sh|bash)[^)]*\).*?(?:\.arg|\.args)\s*\([^)]{0,250}(?:query_string\s*\(|std::env::args|format!\s*\()", re.I | re.S), "Dynamic input appears in a shell command chain; verify use of sh -c and impact.", "remote_code_execution"),
        ("rust-file-path-direct", re.compile(r"(?:std::fs::(?:read|read_to_string|remove_file)|File::open)\s*\([^)]{0,350}(?:query_string\s*\(|std::env::args|format!\s*\()", re.I | re.S), "Dynamic input appears near a filesystem path operation.", "directory_traversal"),
    ],
}


def semgrep_scan(slug: str, version: str, root: Path, timeout: int, include_auto: bool, progress=None):
    executable = shutil.which("semgrep")
    if not executable:
        return [], "Semgrep CLI not installed"
    command = [executable, "scan", "--config", str(LOCAL_RULES), "--json", "--metrics=off", "--quiet", "-j", "1",
               "--max-target-bytes", str(MAX_FILE_BYTES), str(root)]
    if include_auto:
        command[command.index("--json"):command.index("--json")] = ["--config", "auto"]
        command[command.index("--metrics=off")] = "--metrics=on"
    env = dict(__import__("os").environ)
    env["SEMGREP_SEND_METRICS"] = "on" if include_auto else "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    if progress:
        progress("Semgrep analysis", "running bundled and auto-selected rules" if include_auto else "running bundled local rules")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env,
                                encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return [], f"Semgrep timed out after {timeout}s"
    except OSError as exc:
        return [], f"Semgrep could not start: {exc}"
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        detail = result.stderr.strip()[:500] or result.stdout.strip()[:500]
        return [], f"Semgrep returned invalid JSON (exit {result.returncode}): {detail}"
    findings = []
    for item in report.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {}) or {}
        file_path = Path(item.get("path", ""))
        if not file_path.is_absolute():
            file_path = (Path.cwd() / file_path).resolve()
        try:
            relative = str(file_path.relative_to(root.resolve()))
        except ValueError:
            continue
        line = int(item.get("start", {}).get("line", 1) or 1)
        rule_id = "semgrep:" + str(item.get("check_id", "unknown"))
        try:
            file_lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            excerpt = " ".join(file_lines[max(0, line - 2):min(len(file_lines), line + 1)]).strip()[:360]
        except OSError:
            excerpt = str(extra.get("lines", ""))[:360]
        class_hint = metadata.get("wp_class")
        confidence = str(metadata.get("confidence", "medium")).lower()
        signal = str(extra.get("message", "Semgrep security finding"))
        fingerprint = hashlib.sha256(f"{slug}|{version}|{relative}|{line}|{rule_id}|{excerpt}".encode()).hexdigest()[:20]
        findings.append({"signal_id": fingerprint, "plugin_slug": slug, "version": version,
                         "file": relative, "line": line, "rule": rule_id, "signal": signal,
                         "excerpt": excerpt, "class_hint": class_hint, "confidence": confidence,
                         "language": file_path.suffix.lower().lstrip("."), "engine": "semgrep",
                         "review_status": "unreviewed"})
    messages = report.get("errors", [])
    status = None
    if messages:
        status = "Semgrep reported analysis errors: " + "; ".join(
            str(x.get("message", x))[:180] for x in messages[:3])
    elif result.returncode not in {0, 1}:
        status = f"Semgrep exited with code {result.returncode}: {result.stderr.strip()[:400]}"
    if progress:
        progress("Semgrep complete", f"{len(findings)} Semgrep signals")
    return findings, status


def download_and_scan(plugin, source_root: Path, max_files: int, max_findings: int,
                      semgrep_timeout: int, semgrep_auto: bool, progress=None,
                      ai_reviewer: AIReviewer | None = None, ai_max_findings: int = 50,
                      context_filter_enabled: bool = True,
                      reviewed_clean: set[str] | None = None):
    if progress:
        progress("starting", "worker accepted plugin")
    slug, version, path, cached, verification = download_one(plugin, source_root, progress)
    scan_plugin = dict(plugin)
    scan_plugin["version"] = str(verification.get("version_verified") or version)
    result = scan_source_tree(scan_plugin, path, max_files, max_findings, semgrep_timeout,
                              semgrep_auto, progress, ai_reviewer, ai_max_findings, cached,
                              context_filter_enabled=context_filter_enabled,
                              reviewed_clean=reviewed_clean)
    for finding in result[1]:
        finding["version_api"] = version
        finding["version_source"] = verification.get("version_source", "api")
        finding["version_drift"] = bool(verification.get("drift"))
    return result


def scan_source_tree(plugin: dict, path: Path, max_files: int, max_findings: int,
                     semgrep_timeout: int, semgrep_auto: bool, progress=None,
                     ai_reviewer: AIReviewer | None = None, ai_max_findings: int = 50,
                     cached: bool = False, source_hash: str | None = None,
                     context_filter_enabled: bool = True,
                     reviewed_clean: set[str] | None = None):
    slug, version = str(plugin["slug"]), str(plugin["version"])
    if source_hash is None:
        source_hash = fingerprint_source(path, max_files)
    # Reserve capacity for data-flow analysis; lexical leads can otherwise fill the cap first.
    heuristic_cap = max(1, max_findings // 3)
    findings = scan_tree(slug, version, path, max_files, heuristic_cap, progress)
    deep_findings, semgrep_status = semgrep_scan(slug, version, path, semgrep_timeout, semgrep_auto, progress)
    findings.extend(deep_findings[:max(0, max_findings - len(findings))])

    # Exclude signals already reviewed as clean (persisted false positives).
    if reviewed_clean:
        findings = [f for f in findings if f.get("signal_id") not in reviewed_clean]

    # Context-aware false-positive suppression.
    suppressed_findings: list[dict] = []
    if context_filter_enabled and findings:
        try:
            suppressed_findings, findings = context_filter.apply_context_filter(findings, path)
        except Exception as exc:  # never let context filtering abort a scan
            suppressed_findings = []
            if progress:
                progress("context filter", f"context filter skipped ({exc})")
        if progress:
            progress("context filter", f"{len(suppressed_findings)} leads suppressed, {len(findings)} kept")

    if ai_reviewer and findings:
        if progress:
            progress("AI source triage", f"reviewing up to {ai_max_findings} leads")
        reviews = ai_reviewer.review(findings, path, max_findings=ai_max_findings, progress=progress)
        for finding in findings:
            finding["ai_review"] = reviews.get(finding["signal_id"], {
                "disposition": "needs_human", "confidence": "low",
                "summary": "No AI disposition returned; keep the lead open.",
                "auto_closed": False, "evidence_validated": False,
                "provider": "openai-compatible"})
    if progress:
        progress("complete", f"{len(findings)} signals ({len(suppressed_findings)} context-suppressed)")
    return slug, findings, cached, semgrep_status, source_hash, suppressed_findings


def download_compare_and_scan(plugin: dict, staging_root: Path, previous_hash: str | None,
                              max_files: int, max_findings: int, semgrep_timeout: int,
                              semgrep_auto: bool, ai_reviewer: AIReviewer | None,
                              ai_max_findings: int):
    """Fetch a fresh WordPress.org archive; scan only if its source fingerprint drifted."""
    slug = str(plugin["slug"])
    def progress(phase, detail):
        print(f"  [{slug}] {phase}: {detail}", file=sys.stderr, flush=True)
    with tempfile.TemporaryDirectory(prefix="phots-drift-", dir=staging_root) as temporary:
        _, api_version, source, _, verification = download_one(plugin, Path(temporary), progress)
        current_hash = fingerprint_source(source, max_files)
        if previous_hash and current_hash == previous_hash:
            return "unchanged", current_hash, [], None, verification
        scan_plugin = dict(plugin)
        scan_plugin["version"] = str(verification.get("version_verified") or api_version)
        scanned = scan_source_tree(scan_plugin, source, max_files, max_findings,
                                   semgrep_timeout, semgrep_auto, progress,
                                   ai_reviewer, ai_max_findings, cached=False,
                                   source_hash=current_hash)
        _, findings, _, semgrep_status, source_hash, _suppressed = scanned
        for finding in findings:
            finding["version_api"] = api_version
            finding["version_source"] = verification.get("version_source", "api")
            finding["version_drift"] = bool(verification.get("drift"))
        return ("baseline_created" if not previous_hash else "source_changed"), source_hash, findings, semgrep_status, verification


def drift(args):
    """One-shot source drift scan; ordinary stream and catalog scans use completion memory."""
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    staging_root = out / "drift-staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    history_path = out / "phots_stream.sqlite3"
    ai_reviewer = make_ai_reviewer(args, history_path)
    history = sqlite3.connect(history_path, timeout=30)
    history.execute("PRAGMA journal_mode=WAL")
    ensure_history_schema(history)
    baselines = {(row[0], row[1]): row[2] for row in history.execute(
        "SELECT slug,version,source_fingerprint FROM completed").fetchall()}

    plugins = []
    search = (getattr(args, "search", None) or "").strip() or None
    for page in range(1, args.pages + 1):
        params = plugin_query_params(args.browse, page, args.per_page, search)
        try:
            data = get_json(api_url(params))
        except Exception as exc:
            history.close()
            raise RuntimeError(f"Could not read WordPress.org feed page {page}: {exc}") from exc
        page_plugins = data.get("plugins", [])
        plugins.extend(page_plugins)
        print(f"Drift catalog page {page}/{args.pages}: {len(page_plugins)} plugins", file=sys.stderr)
        if len(page_plugins) < args.per_page:
            break
        if args.delay:
            time.sleep(args.delay)

    eligible = [p for p in plugins if p.get("slug") and p.get("version") and p.get("download_link")
                and int(p.get("active_installs", 0) or 0) >= args.min_installs]
    candidates = [p for p in eligible if (str(p["slug"]), str(p["version"])) in baselines]
    known_slugs = {slug for slug, _ in baselines}
    new_versions = [p for p in eligible if str(p["slug"]) in known_slugs
                    and (str(p["slug"]), str(p["version"])) not in baselines]
    print(f"Drift scan: {len(eligible)} eligible feed entries; {len(candidates)} match a previously scanned version; "
          f"{len(new_versions)} are new versions for regular stream mode.", file=sys.stderr)

    store = SupabaseStore() if args.supabase else None
    run_id = str(uuid.uuid4())
    if store:
        store.verify()
        store.upsert_catalog(candidates)
        store.start_run(run_id, len(candidates))
    drift_out = out / "drift"
    drift_out.mkdir(parents=True, exist_ok=True)
    wall_started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    started = time.monotonic()
    results = []
    changed_plugins, all_findings = [], []
    failures = semgrep_failures = unchanged = baselines_created = changed = 0
    jobs = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for plugin in candidates:
            key = (str(plugin["slug"]), str(plugin["version"]))
            jobs[pool.submit(download_compare_and_scan, plugin, staging_root, baselines[key],
                              args.max_files_per_plugin, args.max_findings_per_plugin,
                              args.semgrep_timeout, args.semgrep_auto, ai_reviewer,
                              args.ai_max_findings_per_plugin)] = plugin
        for future in concurrent.futures.as_completed(jobs):
            plugin = jobs[future]
            key = (str(plugin["slug"]), str(plugin["version"]))
            try:
                status, source_hash, findings, semgrep_status, verification = future.result()
                completed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
                results.append({"slug": key[0], "version": key[1], "status": status,
                                "version_verified": verification.get("version_verified"),
                                "version_source": verification.get("version_source"),
                                "version_drift": bool(verification.get("drift")),
                                "previous_fingerprint": baselines[key],
                                "current_fingerprint": source_hash, "signals": len(findings)})
                if status == "unchanged":
                    unchanged += 1
                    # Refresh latest metadata without changing the original scan baseline time.
                    history.execute("UPDATE completed SET name=?,installs=? WHERE slug=? AND version=?",
                                    (str(plugin.get("name") or key[0]),
                                     int(plugin.get("active_installs", 0) or 0), *key))
                else:
                    save_plugin_completion(history, plugin, findings, source_hash, completed_at)
                    try:
                        write_memory_snapshot(out, history)
                    except OSError as exc:
                        print(f"Warning: could not update memory snapshot: {exc}", file=sys.stderr)
                    changed_plugins.append(plugin)
                    all_findings.extend(findings)
                    if status == "baseline_created":
                        baselines_created += 1
                    else:
                        changed += 1
                    if semgrep_status:
                        semgrep_failures += 1
                        results[-1]["semgrep_error"] = semgrep_status
                    if store:
                        store.save_signals(run_id, findings)
                if status == "unchanged":
                    print(f"  unchanged · {key[0]} {key[1]}", file=sys.stderr)
                else:
                    print(f"  {status.replace('_', ' ')} · {key[0]} {key[1]} · {len(findings)} signals",
                          file=sys.stderr)
            except Exception as exc:
                failures += 1
                results.append({"slug": key[0], "version": key[1], "status": "failed",
                                "error": str(exc)[:500]})
                print(f"  drift scan failed · {key[0]} {key[1]}: {exc}", file=sys.stderr)
    history.commit()
    try:
        write_memory_snapshot(out, history)
    except OSError as exc:
        print(f"Warning: could not update memory snapshot: {exc}", file=sys.stderr)
    history.close()

    decisions = []
    for finding in all_findings:
        finding["scope_decision"] = evaluate_scope({
            "asset_type": "plugin",
            "active_installs": next((p.get("active_installs") for p in changed_plugins
                                      if p.get("slug") == finding.get("plugin_slug")), None),
            "vulnerability_type": finding.get("class_hint"), "review_status": "unreviewed",
        }).copy()
        finding["priority"] = "UNCLASSIFIED"
        finding["review_priority"] = review_priority(finding)["code"]
        decisions.append(finding)
    alerts = [item for item in decisions if item.get("scope_decision", {}).get("decision") == "PASS"
              and not (item.get("ai_review") or {}).get("auto_closed")]
    (drift_out / "signals.json").write_text(json.dumps(decisions, indent=2), encoding="utf-8")
    elapsed = max(time.monotonic() - started, 0.001)
    summary = {
        "scan_type": "source_drift",
        "started_at": wall_started,
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "feed": args.browse, "search": search,
        "feed_label": feed_label(args.browse, search),
        "pages": args.pages, "eligible_feed_entries": len(eligible),
        "matched_previous_versions": len(candidates), "new_versions_left_for_stream": len(new_versions),
        "source_changed": changed, "baseline_created": baselines_created,
        "unchanged": unchanged, "failures": failures, "semgrep_failures": semgrep_failures,
        "signals": len(decisions),
        "review_priority_counts": {
            code: sum(review_priority(item)["code"] == code for item in decisions)
            for code in ("P1", "P2", "P3", "UNCLASSIFIED")
        },
        "results": results, "database": str(history_path),
        "scan_report": str(drift_out / "report.html"),
    }
    atomic_json(drift_out / "phots-drift-report.json", summary)
    lines = ["# Phots source drift report", "",
             "> This is a separate, one-shot drift scan. It compares fresh WordPress.org archives with saved fingerprints of supported source files (.php, .py, .go, .rs). A changed fingerprint triggers a new static scan; unchanged versions are not rescanned.", "",
             f"- Feed: **{feed_label(args.browse, search)}** · eligible entries: **{len(eligible)}**",
             f"- Previously scanned versions checked: **{len(candidates)}**",
             f"- Source changed and rescanned: **{changed}**",
             f"- Missing baseline scanned: **{baselines_created}**",
             f"- Unchanged: **{unchanged}** · failures: **{failures}**",
             f"- New versions left for regular stream: **{len(new_versions)}**",
             f"- Candidate signals from changed sources: **{len(decisions)}**", "",
             "## Suggested review priority (not vulnerability severity)", ""]
    drift_priority_order = ("P1", "P2", "P3", "UNCLASSIFIED")
    for code in drift_priority_order:
        count = sum(review_priority(item)["code"] == code for item in decisions)
        lines.append(f"- **{REVIEW_PRIORITY_LABELS[code]}:** {count} — {REVIEW_PRIORITY_BASIS[code]}")
    drift_class_counts = {}
    for finding in decisions:
        label = VULN_LABELS.get(finding.get("class_hint"), "Unclassified security pattern")
        drift_class_counts[label] = drift_class_counts.get(label, 0) + 1
    lines += ["", "## Leads by vulnerability class", ""]
    lines.extend(f"- **{label}:** {count}" for label, count in sorted(drift_class_counts.items()))
    if not drift_class_counts:
        lines.append("No lead categories in this drift report.")
    lines += ["", "## Leads", ""]
    for code in drift_priority_order:
        priority_findings = [item for item in decisions if review_priority(item)["code"] == code]
        if not priority_findings:
            continue
        lines.append(f"### {REVIEW_PRIORITY_LABELS[code]}")
        for finding in priority_findings:
            lines.append(
                f"- `{finding.get('plugin_slug', 'plugin')}` — "
                f"{VULN_LABELS.get(finding.get('class_hint'), 'Unclassified security pattern')} · "
                f"`{finding.get('file', '?')}:{finding.get('line', '?')}` · "
                f"{finding.get('confidence', 'unknown')} confidence · "
                f"{ai_disposition_label(finding)} · signal `{finding.get('signal_id', '')}`"
            )
    lines += ["", "## Plugin results", ""]
    for result in results:
        version_note = (f" · archive version {result['version_verified']}"
                        if result.get("version_drift") else "")
        lines.append(f"- **{result['status']}** — `{result['slug']}` {result['version']}"
                     f"{version_note} · {result.get('signals', 0)} signals")
    if not results:
        lines.append("No previously scanned versions from this feed matched the drift check.")
    (drift_out / "phots-drift-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_human_report(drift_out, changed_plugins, decisions, alerts, failures, semgrep_failures,
                       elapsed, html_path=drift_out / "report.html", write_markdown=False)
    if store:
        store.finish_run(run_id, "completed", scanned_plugins=changed + baselines_created,
                         failed_plugins=failures, signal_count=len(decisions), alert_count=len(alerts))
    print(f"Drift complete: {changed} changed, {baselines_created} baseline(s), {unchanged} unchanged, "
          f"{failures} failed; {len(decisions)} signals. Report: {drift_out / 'phots-drift-report.md'}")


def run(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    history_path = out / "phots_stream.sqlite3"
    ai_reviewer = make_ai_reviewer(args, history_path)
    catalog_path = Path(args.catalog)
    plugins = json.loads(catalog_path.read_text(encoding="utf-8"))
    history = sqlite3.connect(history_path, timeout=30)
    history.execute("PRAGMA journal_mode=WAL")
    ensure_history_schema(history)
    findings = []
    to_scan = []
    remembered_plugins = 0
    for plugin in plugins:
        row = history.execute("SELECT 1 FROM completed WHERE slug=? AND version=?",
                              (plugin.get("slug"), str(plugin.get("version", "")))).fetchone()
        if row:
            records = history.execute("SELECT record FROM signals WHERE slug=? AND version=?",
                                       (plugin.get("slug"), str(plugin.get("version", "")))).fetchall()
            findings.extend(json.loads(record[0]) for record in records)
            remembered_plugins += 1
        else:
            to_scan.append(plugin)
    store = SupabaseStore() if args.supabase else None
    run_id = str(uuid.uuid4())
    if store:
        store.verify()
        store.upsert_catalog(plugins)
        store.start_run(run_id, len(plugins))
    reviewed_clean_path = Path(getattr(args, "reviewed_clean", "output/reviewed_clean.json"))
    if not reviewed_clean_path.is_absolute():
        reviewed_clean_path = out / reviewed_clean_path.name
    reviewed_clean = context_filter.load_reviewed_clean(reviewed_clean_path)
    source_root = out / "source"
    if not shutil.which("semgrep"):
        print("Semgrep is not installed; only built-in heuristics will run. Install with: python -m pip install semgrep",
              file=sys.stderr)
    elif args.semgrep_auto:
        print("Semgrep local WordPress rules and language auto-rules are enabled.", file=sys.stderr)
    started = time.monotonic()
    cached_plugins = 0
    failures = 0
    semgrep_failures = 0
    context_suppressed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(download_and_scan, p, source_root,
                               args.max_files_per_plugin, args.max_findings_per_plugin,
                               args.semgrep_timeout, args.semgrep_auto, None, ai_reviewer,
                               args.ai_max_findings_per_plugin,
                               context_filter_enabled=args.context_filter,
                               reviewed_clean=reviewed_clean): p for p in to_scan}
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            plugin = futures[future]
            try:
                slug, plugin_findings, cached, semgrep_status, source_hash, suppressed = future.result()
                context_suppressed += len(suppressed)
                findings.extend(plugin_findings)
                cached_plugins += int(cached)
                save_plugin_completion(history, plugin, plugin_findings, source_hash)
                try:
                    write_memory_snapshot(out, history)
                except OSError as exc:
                    print(f"Warning: could not update memory snapshot: {exc}", file=sys.stderr)
                if semgrep_status:
                    semgrep_failures += 1
                    if semgrep_failures == 1:
                        print(semgrep_status, file=sys.stderr)
            except (OSError, ValueError, urllib.error.URLError, zipfile.BadZipFile) as exc:
                failures += 1
                print(f"Skipping {plugin.get('slug')}: {exc}", file=sys.stderr)
            completed += 1
            if completed % 10 == 0 or completed == len(futures):
                elapsed = max(time.monotonic() - started, 0.001)
                print(f"Scanned {completed}/{len(futures)} new plugins; reused {remembered_plugins} from Phots memory; "
                      f"{len(findings)} signals; {completed / elapsed:.2f} plugins/s",
                      file=sys.stderr)
    try:
        write_memory_snapshot(out, history)
    except OSError as exc:
        print(f"Warning: could not update memory snapshot: {exc}", file=sys.stderr)
    history.close()
    for finding in findings:
        finding["review_priority"] = review_priority(finding)["code"]
    (out / "signals.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")

    # Human-review decisions are supplied separately. Missing metadata always fails closed.
    review_file = Path(args.review)
    reviews = json.loads(review_file.read_text(encoding="utf-8")) if review_file.exists() else {}
    catalog_by_slug = {p["slug"]: p for p in plugins}
    alerts = []
    decisions = []
    for finding in findings:
        slug = finding["plugin_slug"]
        decision = reviews.get(finding["signal_id"], reviews.get(
            f"{slug}:{finding['file']}:{finding['line']}:{finding['rule']}", {}))
        metadata = catalog_by_slug.get(slug, {})
        hint = finding.get("class_hint")
        supported_hints = HIGH_THREAT | COMMON_DANGEROUS | OTHER_IN_SCOPE
        candidate = {**decision, "asset_type": "plugin",
                     "active_installs": decision.get("active_installs", metadata.get("active_installs")),
                     "vulnerability_type": decision.get("vulnerability_type",
                                                          hint if hint in supported_hints else None),
                     "review_status": decision.get("review_status", "unreviewed")}
        scope_result = evaluate_scope(candidate)
        record = {**finding, "run_id": run_id, "review": decision, "scope_decision": scope_result}
        tier = scope_result.get("tier_class")
        record["priority"] = {"high_threat": "P1_HIGH_THREAT",
                              "common_dangerous": "P2_COMMON_DANGEROUS",
                              "standard_other": "P3_STANDARD_OTHER"}.get(tier, "UNCLASSIFIED")
        record["review_priority"] = review_priority(record)["code"]
        decisions.append(record)
        if scope_result.get("decision") == "PASS" and not (finding.get("ai_review") or {}).get("auto_closed"):
            alerts.append({**record, "scope": "standard_researcher_candidate"})
    (out / "decisions.json").write_text(json.dumps(decisions, indent=2), encoding="utf-8")
    priority_order = {"P1_HIGH_THREAT": 0, "P2_COMMON_DANGEROUS": 1,
                      "P3_STANDARD_OTHER": 2, "UNCLASSIFIED": 3}
    alerts.sort(key=lambda x: (priority_order[x["priority"]], -int(x["review"].get("active_installs", 0) or 0)))
    (out / "alerts.json").write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    elapsed = max(time.monotonic() - started, 0.001)
    write_human_report(out, plugins, decisions, alerts, failures, semgrep_failures, elapsed)
    if store:
        try:
            store.save_signals(run_id, decisions)
            store.save_reviews(decisions)
            store.finish_run(run_id, "completed", scanned_plugins=len(plugins) - failures,
                             failed_plugins=failures, signal_count=len(findings),
                             alert_count=len(alerts))
        except Exception:
            try:
                store.finish_run(run_id, "failed", scanned_plugins=len(plugins) - failures,
                                 failed_plugins=failures, signal_count=len(findings),
                                 alert_count=len(alerts))
            except Exception:
                pass
            raise
    print(f"Source signals: {len(findings)}; alerts: {len(alerts)}; context-suppressed: {context_suppressed}; "
          f"remembered plugin versions: {remembered_plugins}; "
          f"cached source packages: {cached_plugins}; "
          f"download/scan failures: {failures}; Semgrep plugin-level errors/unavailable runs: {semgrep_failures}; "
          f"elapsed: {elapsed:.1f}s")
    try:
        context_filter.save_reviewed_clean(reviewed_clean_path, reviewed_clean)
    except OSError:
        pass


def launch_interactive():
    try:
        return _launch_interactive()
    except EOFError:
        print("No terminal input is available. Run `phots` from an interactive terminal.",
              file=sys.stderr)
        return 2


def choose_discovery_feed():
    choices = {
        "1": ("updated", "Recently updated — best for ongoing release discovery"),
        "2": ("popular", "Popular — broad, high-install plugins"),
        "3": ("new", "New — recently added; often below the install threshold"),
        "4": ("recommended", "Recommended — WordPress.org curated selection"),
        "5": ("beta", "Beta — pre-release plugins"),
        "6": ("top-rated", "Top rated — highly rated plugins"),
    }
    while True:
        print("\n  Where should Phots discover plugins?")
        for key, (_, description) in choices.items():
            print(f"  {key}  {description}")
        print("  7  Search WordPress.org by keyword")
        selection = input("  Discovery source [1-7, Enter = recently updated]: ").strip().lower()
        if not selection:
            return "updated", None
        if selection in choices:
            return choices[selection][0], None
        if selection in {feed for feed, _ in choices.values()}:
            return selection, None
        if selection == "7":
            search = input("  Search terms: ").strip()
            if search:
                return "updated", search
            print("  Enter at least one search term.")
            continue
        print("  Choose 1-7 or a listed feed name.")


def _launch_interactive():
    """Friendly no-argument launcher with a hardware-aware Phots stream setup."""
    # Legacy Windows code pages cannot encode the dashboard's box-drawing characters.
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except (OSError, ValueError):
            pass
    if not sys.stdin.isatty():
        print("The Phots interactive launcher needs a terminal. Run `phots --help` to see available commands.",
              file=sys.stderr)
        return 2
    while True:
        print("\n  PHOTS · WordPress plugin research")
        print("  ─────────────────────────────────")
        print("  1  Start continuous stream")
        print("  2  Scan an existing catalog")
        print("  3  Check for source drift (one-shot, changed versions only)")
        print("  4  Configure optional AI triage")
        print("  5  Audit local Composer/npm dependencies")
        print("  6  Run local WordPress security-audit workflow")
        print("  Q  Exit")
        choice = input("\n  Select a mode [1/2/3/4/5/6/Q]: ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            return 0
        if choice == "1":
            semgrep_enabled = bool(shutil.which("semgrep"))
            recommended, free_gb, basis = concurrency_recommendation(10, semgrep_enabled)
            print("\n  System check")
            print(f"  Free physical RAM: {free_gb if free_gb is not None else 'unknown'} GiB")
            print(f"  CPU cores: {os.cpu_count() or 'unknown'}")
            print(f"  Semgrep: {'available' if semgrep_enabled else 'not found (heuristics only)'}")
            print(f"  Phots recommendation: {recommended} parallel stream(s)")
            print(f"  Sizing: {basis}")
            raw_workers = input(f"\n  Streams [Enter = recommended {recommended}, or 1–10]: ").strip()
            try:
                workers = int(raw_workers) if raw_workers else recommended
            except ValueError:
                print("  Please enter a number from 1 to 10.")
                continue
            if not 1 <= workers <= 10:
                print("  Please enter a number from 1 to 10.")
                continue
            browse, search = choose_discovery_feed()
            output = input("  Output directory [Enter = output]: ").strip() or "output"
            supabase = input("  Also persist to connected Supabase? [y/N]: ").strip().lower() in {"y", "yes"}
            ai_triage = input("  Enable AI lead triage from your configured endpoint? [y/N]: ").strip().lower() in {"y", "yes"}
            if ai_triage:
                try:
                    load_env_file()
                    AIConfig().require_configured()
                except (RuntimeError, ValueError) as exc:
                    print(f"  {exc} Continuing this scan without AI triage.")
                    ai_triage = False
            options = argparse.Namespace(
                out=output, report=None, max_workers=10, workers=workers,
                browse=browse, search=search, pages_per_cycle=2, per_page=100, min_installs=25,
                poll_seconds=60, max_files_per_plugin=5000, max_findings_per_plugin=1000,
                semgrep_timeout=120, semgrep_auto=False, tui=True, supabase=supabase,
                context_filter=True, reviewed_clean="output/reviewed_clean.json",
                ai_triage=ai_triage, ai_base_url=None, ai_model=None,
                ai_max_findings_per_plugin=50)
            print("\n  Starting Phots. Ctrl+C stops cleanly.\n")
            stream(options)
            return 0
        if choice == "2":
            catalog_path = input("  Catalog JSON path [Enter = output/catalog.json]: ").strip() or "output/catalog.json"
            output = input("  Output directory [Enter = output]: ").strip() or "output"
            workers_raw = input("  Parallel workers [Enter = 2]: ").strip()
            try:
                workers = int(workers_raw) if workers_raw else 2
            except ValueError:
                print("  Please enter a number from 1 to 4.")
                continue
            if not 1 <= workers <= 4:
                print("  Please enter a number from 1 to 4.")
                continue
            ai_triage = input("  Enable AI lead triage from your configured endpoint? [y/N]: ").strip().lower() in {"y", "yes"}
            if ai_triage:
                try:
                    load_env_file()
                    AIConfig().require_configured()
                except (RuntimeError, ValueError) as exc:
                    print(f"  {exc} Continuing this scan without AI triage.")
                    ai_triage = False
            options = argparse.Namespace(catalog=catalog_path, review="output/review.json", workers=workers,
                max_files_per_plugin=5000, max_findings_per_plugin=1000, semgrep_timeout=120,
                semgrep_auto=False, out=output, supabase=False, ai_triage=ai_triage,
                ai_base_url=None, ai_model=None, ai_max_findings_per_plugin=50)
            run(options)
            return 0
        if choice == "3":
            browse, search = choose_discovery_feed()
            output = input("  Output directory [Enter = output]: ").strip() or "output"
            supabase = input("  Also persist to connected Supabase? [y/N]: ").strip().lower() in {"y", "yes"}
            ai_triage = input("  Enable AI lead triage from your configured endpoint? [y/N]: ").strip().lower() in {"y", "yes"}
            if ai_triage:
                try:
                    load_env_file()
                    AIConfig().require_configured()
                except (RuntimeError, ValueError) as exc:
                    print(f"  {exc} Continuing this scan without AI triage.")
                    ai_triage = False
            options = argparse.Namespace(
                browse=browse, search=search, pages=2, per_page=100, min_installs=25, delay=1.0,
                workers=2, max_files_per_plugin=5000, max_findings_per_plugin=1000,
                semgrep_timeout=120, semgrep_auto=False, out=output, supabase=supabase,
                ai_triage=ai_triage, ai_base_url=None, ai_model=None,
                ai_max_findings_per_plugin=50)
            drift(options)
            return 0
        if choice == "4":
            try:
                configure_ai_interactively()
            except (RuntimeError, ValueError) as exc:
                print(f"  AI setup failed: {exc}", file=sys.stderr)
            continue
        if choice == "5":
            dependency_audit(argparse.Namespace(root=".", out="output", timeout=300))
            continue
        if choice == "6":
            local_security_audit(argparse.Namespace(
                root=".", out="output", timeout=300,
                include_dependencies=True, run_project_tools=False,
            ))
            continue
        print("  Choose 1, 2, 3, 4, 5, 6, or Q.")


def main():
    if len(sys.argv) == 1:
        raise SystemExit(launch_interactive())
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("catalog", help="collect a bounded WordPress.org plugin catalog")
    p.add_argument("--pages", type=int, default=2)
    p.add_argument("--per-page", type=int, default=100)
    p.add_argument("--browse",
                   choices=["updated", "popular", "new", "recommended", "beta", "top-rated"],
                   default="updated", help="WordPress.org discovery feed (default: recently updated)")
    p.add_argument("--search", help="search WordPress.org by keyword instead of using a browse feed")
    p.add_argument("--min-installs", type=int, default=25)
    p.add_argument("--delay", type=float, default=1.0)
    p.add_argument("--out", default="output")
    p.add_argument("--supabase", action="store_true", help="persist the catalog to the configured Supabase project")
    p.set_defaults(func=catalog)
    p = sub.add_parser("scan", help="download catalog source and scan it offline")
    p.add_argument("--catalog", default="output/catalog.json")
    p.add_argument("--review", default="output/review.json")
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--max-files-per-plugin", type=int, default=5000)
    p.add_argument("--max-findings-per-plugin", type=int, default=1000)
    p.add_argument("--semgrep-timeout", type=int, default=120)
    p.add_argument("--semgrep-auto", action=argparse.BooleanOptionalAction, default=False,
                   help="opt in to Semgrep registry auto-rules and metrics (default: bundled local rules only)")
    p.add_argument("--ai-triage", action="store_true", help="send bounded source excerpts to the configured AI for evidence-based lead triage")
    p.add_argument("--ai-base-url", help="OpenAI-compatible API base URL; may instead be set in PHOTS_AI_BASE_URL")
    p.add_argument("--ai-model", help="model name; may instead be set in PHOTS_AI_MODEL")
    p.add_argument("--ai-max-findings-per-plugin", type=int, default=50,
                   help="maximum AI-reviewed findings per plugin (excess leads remain open)")
    p.add_argument("--context-filter", action=argparse.BooleanOptionalAction, default=True,
                   help="enable context-aware false-positive suppression (default: on)")
    p.add_argument("--reviewed-clean", default="output/reviewed_clean.json",
                   help="path to persistently store signal IDs reviewed as clean false positives")
    p.add_argument("--out", default="output")
    p.add_argument("--supabase", action="store_true", help="persist this run, its signals, and reviewed scope decisions")
    p.set_defaults(func=run)
    p = sub.add_parser("stream", help="continuously scan newly observed WordPress.org plugin versions")
    p.add_argument("--browse",
                   choices=["updated", "popular", "new", "recommended", "beta", "top-rated"],
                   default="updated", help="WordPress.org discovery feed (default: recently updated)")
    p.add_argument("--search", help="search WordPress.org by keyword instead of using a browse feed")
    p.add_argument("--pages-per-cycle", type=int, default=2)
    p.add_argument("--per-page", type=int, default=100)
    p.add_argument("--min-installs", type=int, default=25)
    p.add_argument("--poll-seconds", type=int, default=60)
    p.add_argument("--workers", type=int, default=0, help="parallel streams; 0 selects the memory/CPU recommendation")
    p.add_argument("--max-workers", type=int, default=10, help="upper cap for recommended or explicit streams (max 10)")
    p.add_argument("--max-files-per-plugin", type=int, default=5000)
    p.add_argument("--max-findings-per-plugin", type=int, default=1000)
    p.add_argument("--semgrep-timeout", type=int, default=120)
    p.add_argument("--semgrep-auto", action=argparse.BooleanOptionalAction, default=False,
                   help="opt in to Semgrep registry auto-rules and metrics (default: bundled local rules only)")
    p.add_argument("--ai-triage", action="store_true", help="triage new leads with the configured provider-neutral AI endpoint")
    p.add_argument("--ai-base-url", help="OpenAI-compatible API base URL; may instead be set in PHOTS_AI_BASE_URL")
    p.add_argument("--ai-model", help="model name; may instead be set in PHOTS_AI_MODEL")
    p.add_argument("--ai-max-findings-per-plugin", type=int, default=50,
                   help="maximum AI-reviewed findings per plugin (excess leads remain open)")
    p.add_argument("--context-filter", action=argparse.BooleanOptionalAction, default=True,
                   help="enable context-aware false-positive suppression (default: on)")
    p.add_argument("--reviewed-clean", default="output/reviewed_clean.json",
                   help="path to persistently store signal IDs reviewed as clean false positives")
    p.add_argument("--tui", action=argparse.BooleanOptionalAction, default=sys.stdout.isatty(),
                   help="show the Phots live terminal dashboard (default: on in an interactive terminal)")
    p.add_argument("--report", help="live HTML report path; default: <out>/phots-live-report.html")
    p.add_argument("--log-file", help="append-only live event log; default: <out>/phots-live.log")
    p.add_argument("--handoff-file", help="updated designer handoff snapshot; default: <out>/phots-designer-handoff.md")
    p.add_argument("--out", default="output", help="directory for source cache, SQLite history, and status")
    p.add_argument("--supabase", action="store_true", help="also persist stream catalog and signals to Supabase")
    p.set_defaults(func=stream)
    p = sub.add_parser("drift", help="one-shot fresh-source fingerprint comparison and rescan of changed versions")
    p.add_argument("--browse",
                   choices=["updated", "popular", "new", "recommended", "beta", "top-rated"],
                   default="updated", help="WordPress.org discovery feed (default: recently updated)")
    p.add_argument("--search", help="search WordPress.org by keyword instead of using a browse feed")
    p.add_argument("--pages", type=int, default=2, help="WordPress.org feed pages to compare")
    p.add_argument("--per-page", type=int, default=100)
    p.add_argument("--min-installs", type=int, default=25)
    p.add_argument("--delay", type=float, default=1.0, help="delay between feed pages in seconds")
    p.add_argument("--workers", type=int, default=2, help="parallel fresh downloads and source scans (1–4)")
    p.add_argument("--max-files-per-plugin", type=int, default=5000)
    p.add_argument("--max-findings-per-plugin", type=int, default=1000)
    p.add_argument("--semgrep-timeout", type=int, default=120)
    p.add_argument("--semgrep-auto", action=argparse.BooleanOptionalAction, default=False,
                   help="opt in to Semgrep registry auto-rules and metrics (default: bundled local rules only)")
    p.add_argument("--ai-triage", action="store_true", help="triage changed-source leads with the optional AI endpoint")
    p.add_argument("--ai-base-url", help="OpenAI-compatible API base URL; may instead be set in PHOTS_AI_BASE_URL")
    p.add_argument("--ai-model", help="model name; may instead be set in PHOTS_AI_MODEL")
    p.add_argument("--ai-max-findings-per-plugin", type=int, default=50)
    p.add_argument("--context-filter", action=argparse.BooleanOptionalAction, default=True,
                   help="enable context-aware false-positive suppression (default: on)")
    p.add_argument("--reviewed-clean", default="output/reviewed_clean.json",
                   help="path to persistently store signal IDs reviewed as clean false positives")
    p.add_argument("--out", default="output", help="directory containing Phots history and drift reports")
    p.add_argument("--supabase", action="store_true", help="also persist drift run and findings to Supabase")
    p.set_defaults(func=drift)
    p = sub.add_parser("ai-setup", help="configure the optional AI lead-triage endpoint")
    p.set_defaults(func=lambda _args: configure_ai_interactively())
    p = sub.add_parser("audit", help="inventory local Composer/npm manifests and run installed dependency audits")
    p.add_argument("--root", default=".", help="project directory to inventory (default: current directory)")
    p.add_argument("--out", default="output", help="directory for audit reports and tool output")
    p.add_argument("--timeout", type=int, default=300, help="per-tool timeout in seconds")
    p.set_defaults(func=dependency_audit)
    p = sub.add_parser(
        "security-audit",
        help="inventory local code surfaces and run installed static/dependency audit tools",
    )
    p.add_argument("--root", default=".", help="local project directory to audit (default: current directory)")
    p.add_argument("--out", default="output", help="directory for audit reports and tool output")
    p.add_argument("--timeout", type=int, default=300, help="per-tool timeout in seconds")
    p.add_argument("--no-dependency-audits", dest="include_dependencies", action="store_false",
                   help="skip Composer/npm audits, which may contact configured registries")
    p.add_argument("--run-project-tools", action="store_true",
                   help="run PHPCS/PHPStan/Psalm using the project's configuration; only for trusted projects")
    p.set_defaults(func=local_security_audit, include_dependencies=True)
    args = parser.parse_args()
    if getattr(args, "search", None) is not None:
        args.search = args.search.strip()
        if not args.search:
            parser.error("search terms must not be empty")
    if getattr(args, "pages", 1) < 1 or getattr(args, "per_page", 1) < 1:
        parser.error("pages and per-page must be positive")
    if getattr(args, "workers", 1) < (0 if args.command == "stream" else 1) or getattr(args, "workers", 1) > (10 if args.command == "stream" else 4):
        parser.error("workers must be in the supported range for this command")
    if args.command == "stream":
        if not 1 <= args.max_workers <= 10:
            parser.error("max-workers must be between 1 and 10")
        if args.workers > args.max_workers:
            parser.error("workers cannot exceed max-workers")
        if args.pages_per_cycle < 1 or args.poll_seconds < 1:
            parser.error("pages-per-cycle and poll-seconds must be positive")
        if args.min_installs < 0:
            parser.error("min-installs must be non-negative")
    if args.command == "drift":
        if args.pages < 1 or args.per_page < 1:
            parser.error("pages and per-page must be positive")
        if args.min_installs < 0 or args.delay < 0:
            parser.error("min-installs and delay must be non-negative")
    if args.command in {"audit", "security-audit"} and args.timeout < 1:
        parser.error("timeout must be positive")
    if getattr(args, "max_files_per_plugin", 1) < 1 or getattr(args, "max_findings_per_plugin", 1) < 1:
        parser.error("scan limits must be positive")
    if getattr(args, "semgrep_timeout", 1) < 1:
        parser.error("semgrep-timeout must be positive")
    if getattr(args, "ai_max_findings_per_plugin", 1) < 1:
        parser.error("ai-max-findings-per-plugin must be positive")
    args.func(args)


if __name__ == "__main__":
    main()
