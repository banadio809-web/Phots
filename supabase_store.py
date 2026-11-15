"""Minimal server-side Supabase REST persistence for the local scanner."""

from __future__ import annotations

import getpass
import json
import os
from datetime import datetime, timezone
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_SUPABASE_URL = "https://ogqsngiqokpevjwkzoei.supabase.co"


def load_project_env():
    """Load simple KEY=VALUE entries from the ignored local .env file, if present."""
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    try:
        with open(env_path, encoding="utf-8") as stream:
            for line in stream:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, value = line.split("=", 1)
                name = name.strip()
                value = value.strip().strip("\"'")
                if name and name.replace("_", "").isalnum():
                    os.environ.setdefault(name, value)
    except FileNotFoundError:
        pass


class SupabaseStore:
    def __init__(self, url: str | None = None, key: str | None = None):
        load_project_env()
        self.url = (url or os.getenv("SUPABASE_URL") or DEFAULT_SUPABASE_URL).rstrip("/")
        self.key = key or os.getenv("SUPABASE_SECRET_KEY")
        if self.key and self.key.startswith("replace-with-"):
            self.key = None
        if not self.key and os.isatty(0):
            self.key = getpass.getpass("Supabase secret key (input hidden): ")
        if not self.key:
            raise RuntimeError("Set SUPABASE_SECRET_KEY before using --supabase.")
        parsed = urllib.parse.urlparse(self.url)
        if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".supabase.co"):
            raise RuntimeError("SUPABASE_URL must be an HTTPS Supabase project URL.")

    def request(self, table: str, method: str = "GET", params: dict | None = None,
                body=None, prefer: str | None = None):
        query = urllib.parse.urlencode(params or {})
        url = f"{self.url}/rest/v1/{table}" + (f"?{query}" if query else "")
        headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "WP-Research-Pipeline/0.1",
        }
        if prefer:
            headers["Prefer"] = prefer
        payload = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                return response.read(2 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            detail = exc.read(2048).decode("utf-8", errors="replace")
            raise RuntimeError(f"Supabase {method} {table} returned HTTP {exc.code}: {detail}") from None
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Supabase connection failed: {exc.reason}") from None

    def verify(self):
        self.request("wp_scan_runs", params={"select": "id", "limit": "0"})

    def upsert_catalog(self, plugins: list[dict]):
        rows = [{
            "slug": p["slug"],
            "name": str(p.get("name") or p["slug"]),
            "version": str(p["version"]),
            "active_installs": int(p.get("active_installs", 0) or 0),
            "plugin_url": f"https://wordpress.org/plugins/{p['slug']}/",
            "metadata": p,
        } for p in plugins]
        self._batched_upsert("wp_plugin_catalog", rows, "slug")

    def start_run(self, run_id: str, catalog_count: int):
        self.request("wp_scan_runs", "POST", body={
            "id": run_id, "status": "running", "catalog_count": catalog_count,
            "engine_version": "0.1.0",
        }, prefer="return=minimal")

    def save_signals(self, run_id: str, records: list[dict]):
        rows = [{
            "run_id": run_id,
            "signal_id": r["signal_id"],
            "plugin_slug": r["plugin_slug"],
            "plugin_version": r["version"],
            "file_path": r["file"],
            "line_number": r["line"],
            "rule_id": r["rule"],
            "language": r.get("language", "php"),
            "engine": r.get("engine", "heuristic"),
            "class_hint": r.get("class_hint"),
            "confidence": r.get("confidence", "low"),
            "excerpt": r.get("excerpt", ""),
            "signal": r.get("signal", ""),
            "scope_decision": r.get("scope_decision", {}),
            "priority": r.get("priority", "UNCLASSIFIED"),
        } for r in records]
        self._batched_upsert("wp_scan_signals", rows, "run_id,signal_id")

    def save_reviews(self, records: list[dict]):
        rows = [{
            "signal_id": r["signal_id"],
            "plugin_slug": r["plugin_slug"],
            "plugin_version": r["version"],
            "review": r.get("review", {}),
            "scope_decision": r.get("scope_decision", {}),
        } for r in records if r.get("review")]
        self._batched_upsert("wp_scope_reviews", rows, "signal_id")

    def finish_run(self, run_id: str, status: str, *, scanned_plugins: int,
                   failed_plugins: int, signal_count: int, alert_count: int):
        self.request("wp_scan_runs", "PATCH", params={"id": f"eq.{run_id}"}, body={
            "status": status,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "scanned_plugins": scanned_plugins,
            "failed_plugins": failed_plugins,
            "signal_count": signal_count,
            "alert_count": alert_count,
        }, prefer="return=minimal")

    def _batched_upsert(self, table: str, rows: list[dict], conflict: str):
        for start in range(0, len(rows), 100):
            batch = rows[start:start + 100]
            self.request(table, "POST", params={"on_conflict": conflict}, body=batch,
                         prefer="resolution=merge-duplicates,return=minimal")
