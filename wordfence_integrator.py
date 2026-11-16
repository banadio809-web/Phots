"""Offline-first importer for user-supplied Wordfence rule exports.

This module deliberately does not bundle Wordfence's proprietary rule feed or
pretend that Phots' source patterns are a substitute for Wordfence signatures.
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


SEVERITY_SCORES = {"informational": 0, "low": 2, "medium": 5, "moderate": 5,
                   "high": 8, "critical": 9}
RULE_COLLECTION_KEYS = ("rules", "data", "results", "items")


@dataclass(frozen=True)
class WordfenceRule:
    rule_id: str
    name: str
    description: str = ""
    severity: str = "unknown"
    category: str = ""
    pattern: str = ""


class WordfenceIntegrator:
    """Load JSON/CSV rule exports and annotate findings with explicit rule IDs."""

    def __init__(self, rules_path: str | Path | None = None) -> None:
        self.rules: list[WordfenceRule] = []
        self._rule_map: dict[str, WordfenceRule] = {}
        if rules_path is not None:
            self.load(rules_path)

    def load(self, rules_path: str | Path) -> int:
        path = Path(rules_path)
        if not path.is_file():
            raise FileNotFoundError(f"Wordfence rules file not found: {path}")
        if path.suffix.lower() == ".csv":
            with path.open("r", encoding="utf-8-sig", newline="") as stream:
                entries = list(csv.DictReader(stream))
        else:
            with path.open("r", encoding="utf-8") as stream:
                entries = self._records(json.load(stream))
        self._parse_rules(entries)
        return len(self.rules)

    @staticmethod
    def _records(data: Any) -> list[Mapping[str, Any]]:
        if isinstance(data, dict):
            for key in RULE_COLLECTION_KEYS:
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
        if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
            raise ValueError("Wordfence export must be a JSON list of rule objects")
        return data

    def _parse_rules(self, entries: list[Mapping[str, Any]]) -> None:
        parsed: dict[str, WordfenceRule] = {}
        for entry in entries:
            rule_id = str(entry.get("rule_id", entry.get("wf_rule_id", entry.get("id", "")))).strip()
            if not rule_id:
                continue
            pattern = str(entry.get("pattern", entry.get("regex", "")) or "")
            if pattern:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ValueError(f"Invalid regex for Wordfence rule {rule_id}: {exc}") from exc
            rule = WordfenceRule(
                rule_id=rule_id,
                name=str(entry.get("name", entry.get("wf_rule_name", entry.get("title", ""))) or ""),
                description=str(entry.get("description", entry.get("wf_description", "")) or ""),
                severity=str(entry.get("severity", entry.get("wf_severity", "unknown")) or "unknown").lower(),
                category=str(entry.get("category", "") or ""),
                pattern=pattern,
            )
            parsed[rule_id] = rule
        self._rule_map = parsed
        self.rules = list(parsed.values())

    @staticmethod
    def severity_score(severity: str | None) -> int | None:
        if severity is None:
            return None
        try:
            numeric = float(severity)
        except (TypeError, ValueError):
            return SEVERITY_SCORES.get(str(severity).strip().lower())
        return max(0, min(10, round(numeric)))

    def get_rule_by_id(self, rule_id: str) -> WordfenceRule | None:
        return self._rule_map.get(str(rule_id))

    def enhance_finding(self, finding: Mapping[str, Any]) -> dict[str, Any]:
        enhanced = dict(finding)
        rule_id = enhanced.get("wordfence_rule_id")
        rule = self.get_rule_by_id(rule_id) if rule_id else None
        if not rule:
            return enhanced
        enhanced["wordfence"] = {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "description": rule.description,
            "severity": rule.severity,
            "severity_score": self.severity_score(rule.severity),
            "category": rule.category,
        }
        enhanced.setdefault("class_hint", rule.category or None)
        return enhanced

    def enhance_findings(self, findings: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        return [self.enhance_finding(finding) for finding in findings]


def integrate_wordfence_rules(rules_path: str | Path | None = None) -> WordfenceIntegrator:
    return WordfenceIntegrator(rules_path=rules_path)
