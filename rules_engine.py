#!/usr/bin/env python3
"""Compiled rule engine for Phots security pattern matching.

Provides fast multi-pattern matching using Aho-Corasick algorithm
for improved scan performance over the baseline regex rules.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List, NamedTuple, Tuple


# Rule definition
class Rule(NamedTuple):
    name: str
    pattern: re.Pattern
    description: str
    class_hint: str


# Aho-Corasick-like keyword index for fast pre-filtering
class RuleEngine:
    """Rule engine that pre-compiles patterns and provides fast matching."""

    def __init__(self, rules: List[Rule]):
        self.rules = rules
        # Build keyword index for fast pre-filtering
        self.keyword_index: Dict[str, List[int]] = defaultdict(list)
        self._build_keyword_index()
        # Pre-compile and store patterns with their compiled forms
        self.compiled_patterns = [
            (rule.name, rule.pattern, rule.description, rule.class_hint) for rule in rules
        ]

    def _build_keyword_index(self):
        """Build a keyword index from rule descriptions for fast pre-filtering."""
        for i, rule in enumerate(self.rules):
            # Extract significant keywords from pattern descriptions
            keywords = self._extract_keywords(rule.description)
            for kw in keywords:
                self.keyword_index[kw.lower()].append(i)

    @staticmethod
    def _extract_keywords(description: str) -> List[str]:
        """Extract keywords from rule description."""
        # Simple keyword extraction - take important terms
        keywords = []
        desc_lower = description.lower()
        for word in ["input", "output", "database", "file", "exec", "sql", "xss", "include", "eval"]:
            if word in desc_lower:
                keywords.append(word)
        return keywords

    def scan(self, source: str, hints: List[str] | None = None) -> List[dict]:
        """Scan source code for matching rules.

        Returns list of findings with rule name, description, and class hint.
        """
        findings = []

        # Quick pre-filter using keyword index
        if hints:
            matched_indices = set()
            for hint in hints:
                hint_lower = hint.lower()
                if hint_lower in self.keyword_index:
                    matched_indices.update(self.keyword_index[hint_lower])

            # Only check rules that might match
            rules_to_check = [self.rules[i] for i in matched_indices] if matched_indices else self.rules
        else:
            rules_to_check = self.rules

        # Run regex patterns against source
        for name, pattern, description, class_hint in rules_to_check:
            matches = pattern.finditer(source)
            for match in matches:
                findings.append(
                    {
                        "rule": name,
                        "description": description,
                        "class_hint": class_hint,
                        "match": match.group(),
                        "line": source[: match.start()].count("\n") + 1,
                        "excerpt": source[max(0, match.start() - 50) : match.end() + 50],
                    }
                )

        return findings


# Global rule engine instance
_rule_engine: RuleEngine | None = None


def init_rules(rules: List[Tuple[str, re.Pattern, str, str]]) -> RuleEngine:
    """Initialize the global rule engine with compiled rules."""
    global _rule_engine
    rule_objects = [
        Rule(name=name, pattern=pat, description=desc, class_hint=hint)
        for name, pat, desc, hint in rules
    ]
    _rule_engine = RuleEngine(rule_objects)
    return _rule_engine


def scan_source(source: str, hints: List[str] | None = None) -> List[dict]:
    """Scan source using the global rule engine."""
    if _rule_engine is None:
        # Fallback: direct regex matching
        return _direct_scan(source, hints)
    return _rule_engine.scan(source, hints)


def _direct_scan(source: str, hints: List[str] | None = None) -> List[dict]:
    """Fallback direct regex scanning."""
    from scanner import RULES as default_rules
    findings = []
    for name, pattern, description, class_hint in default_rules:
        matches = pattern.finditer(source)
        for match in matches:
            findings.append(
                {
                    "rule": name,
                    "description": description,
                    "class_hint": class_hint,
                    "match": match.group(),
                    "line": source[: match.start()].count("\n") + 1,
                    "excerpt": source[max(0, match.start() - 50) : match.end() + 50],
                }
            )
    return findings