"""cross_version_dedup.py - Fuzzy deduplication of security findings across software versions using difflib.SequenceMatcher."""

import difflib
from typing import List, Dict, Any, Set, Tuple


class FuzzyDedup:
    """Fuzzy deduplication of security findings using difflib.SequenceMatcher."""

    def __init__(self, similarity_threshold: float = 0.85):
        if not 0.0 <= similarity_threshold <= 1.0:
            raise ValueError("similarity_threshold must be between 0.0 and 1.0")
        self.similarity_threshold = similarity_threshold

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        return difflib.SequenceMatcher(None, a, b).ratio()

    def find_duplicates(
        self, findings: List[Dict[str, Any]]
    ) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
        """Find all pairs of findings above the similarity threshold."""
        duplicates: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
        n = len(findings)
        for i in range(n):
            for j in range(i + 1, n):
                desc_i = findings[i].get("description") or findings[i].get("title") or ""
                desc_j = findings[j].get("description") or findings[j].get("title") or ""
                if not desc_i or not desc_j:
                    continue
                if self._similarity(str(desc_i), str(desc_j)) >= self.similarity_threshold:
                    duplicates.append((findings[i], findings[j]))
        return duplicates

    def group_clusters(self, findings: List[Dict[str, Any]]) -> List[Set[int]]:
        """Group finding indices into duplicate clusters using union-find."""
        parent = list(range(len(findings)))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: int, y: int) -> None:
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        for i in range(len(findings)):
            for j in range(i + 1, len(findings)):
                desc_i = findings[i].get("description") or findings[i].get("title") or ""
                desc_j = findings[j].get("description") or findings[j].get("title") or ""
                if not desc_i or not desc_j:
                    continue
                if self._similarity(str(desc_i), str(desc_j)) >= self.similarity_threshold:
                    union(i, j)

        clusters: Dict[int, Set[int]] = {}
        for idx in range(len(findings)):
            root = find(idx)
            clusters.setdefault(root, set()).add(idx)
        return list(clusters.values())