"""Optional, no-paid-API Patchstack data import and local finding correlation.

Use a user-provided JSON export. Network access is never attempted implicitly;
public API availability and terms can change independently of Phots.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


SEVERITY_SCORES = {"informational": 0, "low": 2, "medium": 5, "moderate": 5,
                   "high": 8, "critical": 9}
COLLECTION_KEYS = ("vulnerabilities", "data", "results", "items")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass(frozen=True)
class PatchstackVulnerability:
    vulnerability_id: str
    name: str
    description: str = ""
    severity: str = "unknown"
    cve: str | None = None
    slug: str | None = None
    affected_versions: str | None = None
    fixed_in: str | None = None
    references: tuple[str, ...] = ()


class PatchstackIntegrator:
    """Import a Patchstack JSON export and cross-reference findings locally."""

    def __init__(self, data_path: str | Path | None = None) -> None:
        self.vulnerabilities: list[PatchstackVulnerability] = []
        self._id_map: dict[str, PatchstackVulnerability] = {}
        self._slug_map: dict[str, list[PatchstackVulnerability]] = {}
        if data_path is not None:
            self.load(data_path)

    def load(self, data_path: str | Path) -> int:
        path = Path(data_path)
        if not path.is_file():
            raise FileNotFoundError(f"Patchstack data file not found: {path}")
        with path.open("r", encoding="utf-8") as stream:
            return self._parse(json.load(stream))

    def fetch_json(self, url: str, *, timeout: float = 15, user_agent: str = "Phots/0.2") -> int:
        """Explicitly fetch a caller-supplied public URL; no API key is supported or required."""
        request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": user_agent})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Could not retrieve Patchstack JSON data: {exc}") from exc
        return self._parse(payload)

    @staticmethod
    def _records(data: Any) -> list[Mapping[str, Any]]:
        if isinstance(data, dict):
            for key in COLLECTION_KEYS:
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
            else:
                data = [data]
        if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
            raise ValueError("Patchstack data must be a JSON object or list of vulnerability objects")
        return data

    def _parse(self, data: Any) -> int:
        id_map: dict[str, PatchstackVulnerability] = {}
        slug_map: dict[str, list[PatchstackVulnerability]] = {}
        for item in self._records(data):
            vulnerability_id = str(item.get("id", item.get("vulnerability_id", item.get("ps_rule_id", "")))).strip()
            name = str(item.get("name", item.get("title", item.get("ps_rule_name", ""))) or "")
            if not vulnerability_id and not name:
                continue
            raw_cve = str(item.get("cve", item.get("cve_id", item.get("ps_cve", ""))) or "").strip()
            cve = raw_cve.upper() if CVE_PATTERN.fullmatch(raw_cve) else None
            references = item.get("references", []) or []
            if isinstance(references, str):
                references = [references]
            record = PatchstackVulnerability(
                vulnerability_id=vulnerability_id or name,
                name=name or vulnerability_id,
                description=str(item.get("description", item.get("ps_description", "")) or ""),
                severity=str(item.get("severity", item.get("ps_severity", "unknown")) or "unknown").lower(),
                cve=cve,
                slug=str(item.get("slug", item.get("plugin_slug", "")) or "").strip().lower() or None,
                affected_versions=(str(item.get("affected_versions", item.get("affected_version", "")) or "").strip() or None),
                fixed_in=(str(item.get("fixed_in", item.get("patched_in", "")) or "").strip() or None),
                references=tuple(str(ref) for ref in references if ref),
            )
            id_map[record.vulnerability_id] = record
            if record.slug:
                slug_map.setdefault(record.slug, []).append(record)
        self._id_map = id_map
        self._slug_map = slug_map
        self.vulnerabilities = list(id_map.values())
        return len(self.vulnerabilities)

    @staticmethod
    def severity_score(severity: str | None) -> int | None:
        if severity is None:
            return None
        try:
            numeric = float(severity)
        except (TypeError, ValueError):
            return SEVERITY_SCORES.get(str(severity).strip().lower())
        return max(0, min(10, round(numeric)))

    def get_vulnerability_by_id(self, vulnerability_id: str) -> PatchstackVulnerability | None:
        return self._id_map.get(str(vulnerability_id))

    def correlate_finding(self, finding: Mapping[str, Any]) -> dict[str, Any]:
        enriched = dict(finding)
        explicit_id = enriched.get("patchstack_vulnerability_id", enriched.get("patchstack_rule_id"))
        record = self.get_vulnerability_by_id(explicit_id) if explicit_id else None
        slug = str(enriched.get("plugin_slug", enriched.get("slug", ""))).strip().lower()
        if record is None and slug:
            candidates = self._slug_map.get(slug, [])
            record = candidates[0] if len(candidates) == 1 else None
        if record is None:
            return enriched
        enriched["patchstack"] = {
            "vulnerability_id": record.vulnerability_id,
            "name": record.name,
            "severity": record.severity,
            "severity_score": self.severity_score(record.severity),
            "cve": record.cve,
            "slug": record.slug,
            "affected_versions": record.affected_versions,
            "fixed_in": record.fixed_in,
            "references": list(record.references),
        }
        if record.cve:
            enriched.setdefault("cve", record.cve)
        return enriched

    def correlate_findings(self, findings: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        return [self.correlate_finding(finding) for finding in findings]


def integrate_patchstack_vulns(data_path: str | Path | None = None) -> PatchstackIntegrator:
    return PatchstackIntegrator(data_path=data_path)
