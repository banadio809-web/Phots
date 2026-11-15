#!/usr/bin/env python3
"""Offline WordPress.org plugin source triage. Signals are not confirmed vulnerabilities."""

from __future__ import annotations

import argparse
import bisect
from collections import deque
import concurrent.futures
import ctypes
import os
import hashlib
import heapq
import html
import json
import re
import queue as queue_module
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from scope_filter import (COMMON_DANGEROUS, HIGH_THREAT, OTHER_IN_SCOPE,
                          evaluate as evaluate_scope)
from ai_triage import AIConfig, AIMemory, AIReviewer, load_env_file
from supabase_store import SupabaseStore

API = "https://api.wordpress.org/plugins/info/1.2/"
UA = "WP-Research-Triage/0.1 (polite, read-only source scanner)"
MAX_ZIP_BYTES = 100 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024

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
LOCAL_RULES = Path(__file__).resolve().parent / "rules" / "wordpress_multilang.yml"

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
    for record in decisions:
        buckets.setdefault(report_bucket(record), []).append(record)
    order = ["AI bug candidate — unconfirmed", "AI review needs human follow-up",
             "AI false-positive suggestion — not closed", "AI review cap — lead remains open", "Review first — stronger automated signal",
             "Review — plausible security lead", "Unclassified — needs manual triage",
             "AI closed as likely false positive", "Eligible candidate — human review required"]
    lines = ["# WordPress Plugin Scan Report", "",
             "> Automated source review produces leads, not confirmed vulnerabilities or severity ratings.", "",
             "## At a glance", "",
             f"- Plugins in this run: **{stream_status.get('scanned', len(plugins)) if stream_status else len(plugins)}**",
             f"- Candidate signals: **{stream_status.get('signal_count', len(decisions)) if stream_status else len(decisions)}**",
             f"- Eligible candidates: **{len(alerts)}** (still require human verification)",
             f"- Download/scan failures: **{failures}**",
             f"- Semgrep unavailable/error runs: **{semgrep_failures}**",
             f"- Elapsed: **{elapsed:.1f} seconds**", "",
             "## Review groups", ""]
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
    for bucket in order:
        lines.append(f"- **{bucket}:** {len(buckets.get(bucket, []))}")
    if not decisions:
        lines += ["", "No candidate signals were found in the scanned source. This does not prove the plugins are free of vulnerabilities."]
    for bucket in order:
        records = buckets.get(bucket, [])
        if not records:
            continue
        lines += ["", f"## {bucket}", ""]
        for index, item in enumerate(records, 1):
            meta = catalog.get(item["plugin_slug"], {})
            display = meta.get("name") or item["plugin_slug"]
            decision = item.get("scope_decision", {})
            scope = decision.get("decision", "REVIEW")
            why = "; ".join(decision.get("reasons", [])) or "Required eligibility evidence has not been reviewed."
            lines += [f"### {index}. {display} ({item['plugin_slug']})",
                      f"- **What was flagged:** {VULN_LABELS.get(item.get('class_hint'), 'Unclassified security pattern')}",
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
    for bucket in order:
        for item in buckets.get(bucket, []):
            decision = item.get("scope_decision", {})
            meta = catalog.get(item["plugin_slug"], {})
            cards.append(f"<article><h2>{html.escape(str(meta.get('name') or item['plugin_slug']))}</h2>"
                         f"<p><b>{html.escape(bucket)}</b> · {html.escape(str(decision.get('decision', 'REVIEW')))} · "
                         f"{html.escape(VULN_LABELS.get(item.get('class_hint'), 'Unclassified security pattern'))}</p>"
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
            "<h1>WordPress Plugin Scan Report</h1><p class='note'>Automated leads only; not confirmed vulnerabilities or severity ratings.</p>"
            f"<p>{stream_status.get('scanned', len(plugins)) if stream_status else len(plugins)} plugins · {stream_status.get('signal_count', len(decisions)) if stream_status else len(decisions)} signals · {len(alerts)} eligible candidates pending human verification · {failures} scan failures</p>"
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
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(page, encoding="utf-8")
    temp.replace(target)


def memory_available_bytes():
    """Return currently available physical memory without an optional dependency."""
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
            return int(state.ullAvailPhys)
    try:
        pages = os.sysconf("SC_AVPHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return int(pages * page_size)
    except (ValueError, OSError, AttributeError):
        return None


def concurrency_recommendation(max_workers: int, semgrep_enabled: bool):
    available = memory_available_bytes()
    cores = max(1, os.cpu_count() or 1)
    # Reserve 35% of current free RAM for the OS and unrelated applications.
    per_worker = 2 * 1024**3 if semgrep_enabled else 512 * 1024**2
    memory_slots = max(1, int((available * 0.65) // per_worker)) if available else 1
    recommended = max(1, min(max_workers, cores, memory_slots))
    available_gb = round(available / 1024**3, 1) if available is not None else None
    basis = f"{cores} logical CPU cores; reserve 35% of free RAM; budget {per_worker // 1024**2} MiB per stream"
    return recommended, available_gb, basis


def atomic_json(path: Path, value):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
    temp.replace(path)


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
            notes.append(f"Resource pressure risk: {state['workers']} streams are active, above the RAM-based recommendation of {state['recommended']}.")
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
        temp = self.handoff_path.with_suffix(self.handoff_path.suffix + ".tmp")
        try:
            temp.write_text("\n".join(lines), encoding="utf-8")
            temp.replace(self.handoff_path)
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
    latest = recent[-5:]
    findings = [f"{r['plugin_slug']} · {r.get('class_hint') or 'unclassified'} · {r['file']}:{r['line']}" for r in latest]
    if not findings:
        findings = ["No signals yet. Phots is warming up…"]
    phase = "PAUSED" if paused else state.get("status", "STARTING").upper()
    headline = [f"{cyan}██████╗ ██╗  ██╗ ██████╗ ████████╗███████╗{reset}",
                f"{cyan}██╔══██╗██║  ██║██╔═══██╗╚══██╔══╝██╔════╝{reset}",
                f"{cyan}██████╔╝███████║██║   ██║   ██║   ███████╗{reset}",
                f"{cyan}██╔═══╝ ██╔══██║██║   ██║   ██║   ╚════██║{reset}",
                f"{cyan}██║     ██║  ██║╚██████╔╝   ██║   ███████║  PLUGIN RESEARCH STREAM{reset}",
                f"{muted}Source-only analysis · human validation required · Ctrl+C stops cleanly{reset}"]
    body = []
    body.extend(box("LIVE STATUS", [
        f"Mode: {phase}     Plugins scanned: {state.get('scanned', 0)}     New signals: {state.get('signal_count', 0)}",
        f"Active workers: {state.get('active', 0)}/{state.get('workers', 1)}     Queue: {state.get('queued', 0)}     Errors: {state.get('failures', 0)}",
        f"AI triage: {state.get('ai_reviewed', 0)} reviewed · {state.get('ai_closed', 0)} false-positive closures · {state.get('ai_bug_candidates', 0)} bug candidates · {state.get('ai_errors', 0)} errors",
        f"AI endpoint: {'enabled · ' + str(state.get('ai_model')) if state.get('ai_enabled') else 'disabled'}",
        f"Latest: {state.get('last_plugin') or 'waiting for first plugin'}",
        f"Retry status: {state.get('retry_note', 'none')}",
        f"Latest issue: {state.get('last_error', 'none')}",
        f"Semgrep detail: {state.get('last_semgrep_error', 'none')}",
        f"Feed note: {state.get('scan_note', 'none')}",
        f"Uptime: {state.get('uptime', '0s')}     Poll interval: {state.get('poll_seconds', 30)}s",
    ], green))
    if state.get("job_lines"):
        body.extend(box("WHAT EACH WORKER IS DOING", state["job_lines"], cyan))
    body.extend(box("RESOURCE FIT", [
        f"Free physical memory now: {state.get('current_memory_gb', state.get('available_memory_gb', 'unknown'))} GiB",
        f"Recommended streams: {state.get('recommended', 1)} of max {state.get('max_workers', 10)}",
        f"Quick fit check (1/2/3/4/10): {state.get('stream_options', 'calculating')}",
        f"Basis: {state.get('recommendation', 'checking system resources')}",
        f"Output: {state.get('report_path', 'phots-live-report.html')}",
        f"Live log: {state.get('log_path', 'phots-live.log')}",
        f"Designer handoff: {state.get('handoff_path', 'phots-designer-handoff.md')}",
    ], blue))
    body.extend(box("LATEST SIGNALS · leads, not confirmed bugs", findings, yellow))
    body.extend([f"{muted}Controls: Ctrl+C stop and save  ·  report refreshes after each plugin{reset}"])
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
    recommended, available_gb, basis = concurrency_recommendation(max_workers, bool(shutil.which("semgrep")))
    workers = args.workers or recommended
    workers = min(max_workers, workers)
    if workers > recommended:
        print(f"Phots note: {workers} streams exceeds the current RAM-based recommendation of {recommended}; "
              "Semgrep may increase memory pressure.", file=sys.stderr)
    option_fit = ", ".join(f"{n}: {'within recommendation' if n <= recommended else 'above recommendation'}"
                           for n in (1, 2, 3, 4, 10))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    state = {"started_at": now, "status": "running", "workers": workers,
             "recommended": recommended, "available_memory_gb": available_gb,
             "recommendation": basis, "stream_options": option_fit,
             "max_workers": max_workers, "report_path": str(report_path),
             "log_path": str(log_path), "handoff_path": str(handoff_path),
             "poll_seconds": args.poll_seconds, "scanned": 0, "signal_count": 0,
             "failures": 0, "last_plugin": None, "active": 0, "queued": 0}
    state["ai_enabled"] = bool(ai_reviewer)
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
        state["job_lines"] = job_lines[-workers:] or ["Workers are idle; checking for new plugin versions."]
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
        write_human_report(report_out, plugins, decisions, alerts, state["failures"],
                           state.get("semgrep_failures", 0), time.monotonic() - started,
                           stream_status=report_state, html_path=report_path, write_markdown=False)
        atomic_json(out / "phots-stream-status.json", report_state)
        write_memory_snapshot(out, db)
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
                   free_ram_gib=available_gb, cpu_cores=os.cpu_count(), feed=args.browse,
                   min_installs=args.min_installs, semgrep=bool(shutil.which("semgrep")),
                   ai_enabled=bool(ai_reviewer), ai_model=(ai_reviewer.config.model if ai_reviewer else None),
                   supabase=bool(store), report=report_path)
    publish()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers + 1) as pool:
            while True:
                # Discover a bounded batch; versions already persisted in SQLite are skipped on restart.
                discovered = []
                feed_used = args.browse
                for page in range(1, args.pages_per_cycle + 1):
                    params = {"action": "query_plugins", "request[browse]": args.browse,
                              "request[per_page]": str(args.per_page), "request[page]": str(page),
                              "request[fields][active_installs]": "1"}
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
                        live_log.event("ERROR", "catalog_request_failed", feed=args.browse,
                                       page=page, detail=last_error)
                        break
                    discovered.extend(data.get("plugins", []))
                    live_log.event("INFO", "catalog_page", feed=args.browse, page=page,
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
                if not batch and args.browse != "popular":
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
                        params = {"action": "query_plugins", "request[browse]": "popular",
                                  "request[per_page]": str(args.per_page), "request[page]": str(page),
                                  "request[fields][active_installs]": "1"}
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
                                              ai_reviewer, args.ai_max_findings_per_plugin)
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
                                slug, found, cached, semgrep_status, source_hash = future.result()
                                completed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
                                meta = {"slug": slug, "version": str(plugin["version"]),
                                        "name": str(plugin.get("name") or slug),
                                        "installs": int(plugin.get("active_installs", 0) or 0)}
                                save_plugin_completion(db, plugin, found, source_hash, completed_at)
                                write_memory_snapshot(out, db)
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
                                if retry_attempts.get(failed_key, 1) < 3:
                                    seen_this_session.discard(failed_key)
                                    delay = min(60 * (2 ** (retry_attempts[failed_key] - 1)), 600)
                                    retry_after[failed_key] = time.monotonic() + delay
                                    state["retry_note"] = f"Retrying {failed_key[0]} after {delay}s (attempt {retry_attempts[failed_key] + 1}/3)."
                                    live_log.event("WARN", "plugin_retry_scheduled", plugin=failed_key[0],
                                                   attempt=retry_attempts[failed_key], delay_seconds=delay)
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
            try:
                store.finish_run(run_id, "completed", scanned_plugins=state["scanned"],
                                 failed_plugins=state["failures"], signal_count=state["signal_count"],
                                 alert_count=0)
            except Exception as exc:
                state["supabase_error"] = str(exc)[:300]
        print(f"\nPhots stopped cleanly. Live report: {report_path}")


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


def catalog(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    plugins = []
    for page in range(1, args.pages + 1):
        params = {"action": "query_plugins", "request[browse]": args.browse,
                  "request[per_page]": str(args.per_page), "request[page]": str(page),
                  "request[fields][active_installs]": "1"}
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
    print(f"Saved {len(eligible)} plugins above the install threshold to {out / 'catalog.json'}")


def safe_extract(data: bytes, dest: Path):
    if len(data) > MAX_ZIP_BYTES:
        raise ValueError("archive exceeds configured compressed size limit")
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    with zipfile.ZipFile(__import__("io").BytesIO(data)) as zf:
        if len(zf.infolist()) > 100_000:
            raise ValueError("archive contains too many entries")
        for info in zf.infolist():
            target = (dest / info.filename).resolve()
            if dest.resolve() not in target.parents and target != dest.resolve():
                raise ValueError("archive contains an unsafe path")
            total += info.file_size
            if total > MAX_ZIP_BYTES:
                raise ValueError("archive exceeds configured expanded size limit")
        zf.extractall(dest)


def download_one(plugin, root: Path, progress=None):
    slug = plugin["slug"]
    version = str(plugin["version"])
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", slug) or slug in {".", ".."}:
        raise ValueError("plugin slug contains unsupported path characters")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", version) or version in {".", ".."}:
        raise ValueError("plugin version contains unsupported path characters")
    target = root / slug / version
    marker = target / ".complete"
    if marker.is_file():
        if progress:
            progress("source cache", "reusing downloaded archive")
        return slug, version, target, True
    package_url = urllib.parse.urlparse(plugin["download_link"])
    if package_url.scheme != "https" or package_url.hostname != "downloads.wordpress.org":
        raise ValueError("package URL is not an HTTPS WordPress.org download")
    if progress:
        progress("downloading ZIP", "requesting archive from downloads.wordpress.org")
    data = fetch_bytes(plugin["download_link"], MAX_ZIP_BYTES, 60)
    if progress:
        progress("extracting source", f"received {len(data) / 1024 / 1024:.1f} MiB")
    safe_extract(data, target)
    marker.write_text("ok\n", encoding="utf-8")
    if progress:
        progress("source ready", "archive safely extracted")
    return slug, version, target, False


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
                      ai_reviewer: AIReviewer | None = None, ai_max_findings: int = 50):
    if progress:
        progress("starting", "worker accepted plugin")
    slug, version, path, cached = download_one(plugin, source_root, progress)
    return scan_source_tree(plugin, path, max_files, max_findings, semgrep_timeout,
                             semgrep_auto, progress, ai_reviewer, ai_max_findings, cached)


def scan_source_tree(plugin: dict, path: Path, max_files: int, max_findings: int,
                     semgrep_timeout: int, semgrep_auto: bool, progress=None,
                     ai_reviewer: AIReviewer | None = None, ai_max_findings: int = 50,
                     cached: bool = False, source_hash: str | None = None):
    slug, version = str(plugin["slug"]), str(plugin["version"])
    if source_hash is None:
        source_hash = fingerprint_source(path, max_files)
    # Reserve capacity for data-flow analysis; lexical leads can otherwise fill the cap first.
    heuristic_cap = max(1, max_findings // 3)
    findings = scan_tree(slug, version, path, max_files, heuristic_cap, progress)
    deep_findings, semgrep_status = semgrep_scan(slug, version, path, semgrep_timeout, semgrep_auto, progress)
    findings.extend(deep_findings[:max(0, max_findings - len(findings))])
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
        progress("complete", f"{len(findings)} total signals")
    return slug, findings, cached, semgrep_status, source_hash


def download_compare_and_scan(plugin: dict, staging_root: Path, previous_hash: str | None,
                              max_files: int, max_findings: int, semgrep_timeout: int,
                              semgrep_auto: bool, ai_reviewer: AIReviewer | None,
                              ai_max_findings: int):
    """Fetch a fresh WordPress.org archive; scan only if its source fingerprint drifted."""
    slug = str(plugin["slug"])
    def progress(phase, detail):
        print(f"  [{slug}] {phase}: {detail}", file=sys.stderr, flush=True)
    with tempfile.TemporaryDirectory(prefix="phots-drift-", dir=staging_root) as temporary:
        _, _, source, _ = download_one(plugin, Path(temporary), progress)
        current_hash = fingerprint_source(source, max_files)
        if previous_hash and current_hash == previous_hash:
            return "unchanged", current_hash, [], None
        scanned = scan_source_tree(plugin, source, max_files, max_findings,
                                   semgrep_timeout, semgrep_auto, progress,
                                   ai_reviewer, ai_max_findings, cached=False,
                                   source_hash=current_hash)
        _, findings, _, semgrep_status, source_hash = scanned
        return ("baseline_created" if not previous_hash else "source_changed"), source_hash, findings, semgrep_status


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
    for page in range(1, args.pages + 1):
        params = {"action": "query_plugins", "request[browse]": args.browse,
                  "request[per_page]": str(args.per_page), "request[page]": str(page),
                  "request[fields][active_installs]": "1"}
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
                status, source_hash, findings, semgrep_status = future.result()
                completed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
                results.append({"slug": key[0], "version": key[1], "status": status,
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
                    write_memory_snapshot(out, history)
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
    write_memory_snapshot(out, history)
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
        decisions.append(finding)
    alerts = [item for item in decisions if item.get("scope_decision", {}).get("decision") == "PASS"
              and not (item.get("ai_review") or {}).get("auto_closed")]
    (drift_out / "signals.json").write_text(json.dumps(decisions, indent=2), encoding="utf-8")
    elapsed = max(time.monotonic() - started, 0.001)
    summary = {
        "scan_type": "source_drift",
        "started_at": wall_started,
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "feed": args.browse, "pages": args.pages, "eligible_feed_entries": len(eligible),
        "matched_previous_versions": len(candidates), "new_versions_left_for_stream": len(new_versions),
        "source_changed": changed, "baseline_created": baselines_created,
        "unchanged": unchanged, "failures": failures, "semgrep_failures": semgrep_failures,
        "signals": len(decisions), "results": results, "database": str(history_path),
        "scan_report": str(drift_out / "report.html"),
    }
    atomic_json(drift_out / "phots-drift-report.json", summary)
    lines = ["# Phots source drift report", "",
             "> This is a separate, one-shot drift scan. It compares fresh WordPress.org archives with saved fingerprints of supported source files (.php, .py, .go, .rs). A changed fingerprint triggers a new static scan; unchanged versions are not rescanned.", "",
             f"- Feed: **{args.browse}** · eligible entries: **{len(eligible)}**",
             f"- Previously scanned versions checked: **{len(candidates)}**",
             f"- Source changed and rescanned: **{changed}**",
             f"- Missing baseline scanned: **{baselines_created}**",
             f"- Unchanged: **{unchanged}** · failures: **{failures}**",
             f"- New versions left for regular stream: **{len(new_versions)}**",
             f"- Candidate signals from changed sources: **{len(decisions)}**", "", "## Plugin results", ""]
    for result in results:
        lines.append(f"- **{result['status']}** — `{result['slug']}` {result['version']} · {result.get('signals', 0)} signals")
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
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(download_and_scan, p, source_root,
                               args.max_files_per_plugin, args.max_findings_per_plugin,
                               args.semgrep_timeout, args.semgrep_auto, None, ai_reviewer,
                               args.ai_max_findings_per_plugin): p for p in to_scan}
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            plugin = futures[future]
            try:
                slug, plugin_findings, cached, semgrep_status, source_hash = future.result()
                findings.extend(plugin_findings)
                cached_plugins += int(cached)
                save_plugin_completion(history, plugin, plugin_findings, source_hash)
                write_memory_snapshot(out, history)
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
    write_memory_snapshot(out, history)
    history.close()
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
    print(f"Source signals: {len(findings)}; alerts: {len(alerts)}; remembered plugin versions: {remembered_plugins}; "
          f"cached source packages: {cached_plugins}; "
          f"download/scan failures: {failures}; Semgrep plugin-level errors/unavailable runs: {semgrep_failures}; "
          f"elapsed: {elapsed:.1f}s")


def launch_interactive():
    """Friendly no-argument launcher with a hardware-aware Phots stream setup."""
    if not sys.stdin.isatty():
        print("Choose a mode: python scanner.py stream, scan, drift, or catalog", file=sys.stderr)
        return 2
    while True:
        print("\n  PHOTS · WordPress plugin research")
        print("  ─────────────────────────────────")
        print("  1  Start continuous stream")
        print("  2  Scan an existing catalog")
        print("  3  Check for source drift (one-shot, changed versions only)")
        print("  Q  Exit")
        choice = input("\n  Select a mode [1/2/3/Q]: ").strip().lower()
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
            browse = input("  WordPress.org feed [popular/new, Enter = popular]: ").strip().lower() or "popular"
            if browse not in {"new", "popular", "recommended", "beta"}:
                print("  Unknown feed; using popular.")
                browse = "popular"
            output = input("  Output directory [Enter = work]: ").strip() or "work"
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
                browse=browse, pages_per_cycle=2, per_page=100, min_installs=25,
                poll_seconds=60, max_files_per_plugin=5000, max_findings_per_plugin=1000,
                semgrep_timeout=120, semgrep_auto=False, tui=True, supabase=supabase,
                ai_triage=ai_triage, ai_base_url=None, ai_model=None,
                ai_max_findings_per_plugin=50)
            print("\n  Starting Phots. Ctrl+C stops cleanly.\n")
            stream(options)
            return 0
        if choice == "2":
            catalog_path = input("  Catalog JSON path [Enter = work/catalog.json]: ").strip() or "work/catalog.json"
            output = input("  Output directory [Enter = work]: ").strip() or "work"
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
            options = argparse.Namespace(catalog=catalog_path, review="review.json", workers=workers,
                max_files_per_plugin=5000, max_findings_per_plugin=1000, semgrep_timeout=120,
                semgrep_auto=False, out=output, supabase=False, ai_triage=ai_triage,
                ai_base_url=None, ai_model=None, ai_max_findings_per_plugin=50)
            run(options)
            return 0
        if choice == "3":
            browse = input("  WordPress.org feed [popular/new, Enter = popular]: ").strip().lower() or "popular"
            if browse not in {"new", "popular", "recommended", "beta"}:
                print("  Unknown feed; using popular.")
                browse = "popular"
            output = input("  Output directory [Enter = work]: ").strip() or "work"
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
                browse=browse, pages=2, per_page=100, min_installs=25, delay=1.0,
                workers=2, max_files_per_plugin=5000, max_findings_per_plugin=1000,
                semgrep_timeout=120, semgrep_auto=False, out=output, supabase=supabase,
                ai_triage=ai_triage, ai_base_url=None, ai_model=None,
                ai_max_findings_per_plugin=50)
            drift(options)
            return 0
        print("  Choose 1, 2, 3, or Q.")


def main():
    if len(sys.argv) == 1:
        raise SystemExit(launch_interactive())
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("catalog", help="collect a bounded WordPress.org plugin catalog")
    p.add_argument("--pages", type=int, default=2)
    p.add_argument("--per-page", type=int, default=100)
    p.add_argument("--browse", choices=["popular", "new", "recommended", "beta"], default="popular")
    p.add_argument("--min-installs", type=int, default=25)
    p.add_argument("--delay", type=float, default=1.0)
    p.add_argument("--out", default="work")
    p.add_argument("--supabase", action="store_true", help="persist the catalog to the configured Supabase project")
    p.set_defaults(func=catalog)
    p = sub.add_parser("scan", help="download catalog source and scan it offline")
    p.add_argument("--catalog", default="work/catalog.json")
    p.add_argument("--review", default="review.json")
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
    p.add_argument("--out", default="work")
    p.add_argument("--supabase", action="store_true", help="persist this run, its signals, and reviewed scope decisions")
    p.set_defaults(func=run)
    p = sub.add_parser("stream", help="continuously scan newly observed WordPress.org plugin versions")
    p.add_argument("--browse", choices=["popular", "new", "recommended", "beta"], default="popular")
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
    p.add_argument("--tui", action=argparse.BooleanOptionalAction, default=sys.stdout.isatty(),
                   help="show the Phots live terminal dashboard (default: on in an interactive terminal)")
    p.add_argument("--report", help="live HTML report path; default: <out>/phots-live-report.html")
    p.add_argument("--log-file", help="append-only live event log; default: <out>/phots-live.log")
    p.add_argument("--handoff-file", help="updated designer handoff snapshot; default: <out>/phots-designer-handoff.md")
    p.add_argument("--out", default="work", help="directory for source cache, SQLite history, and status")
    p.add_argument("--supabase", action="store_true", help="also persist stream catalog and signals to Supabase")
    p.set_defaults(func=stream)
    p = sub.add_parser("drift", help="one-shot fresh-source fingerprint comparison and rescan of changed versions")
    p.add_argument("--browse", choices=["popular", "new", "recommended", "beta"], default="popular")
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
    p.add_argument("--out", default="work", help="directory containing Phots history and drift reports")
    p.add_argument("--supabase", action="store_true", help="also persist drift run and findings to Supabase")
    p.set_defaults(func=drift)
    args = parser.parse_args()
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
    if getattr(args, "max_files_per_plugin", 1) < 1 or getattr(args, "max_findings_per_plugin", 1) < 1:
        parser.error("scan limits must be positive")
    if getattr(args, "semgrep_timeout", 1) < 1:
        parser.error("semgrep-timeout must be positive")
    if getattr(args, "ai_max_findings_per_plugin", 1) < 1:
        parser.error("ai-max-findings-per-plugin must be positive")
    args.func(args)


if __name__ == "__main__":
    main()
