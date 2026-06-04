from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from core.enums import ASICategory, Severity
from core.models import Finding, CategorySummary, EvalReport


class FindingAggregator:
    """Aggregates and deduplicates security findings."""

    def __init__(self, dedup_similarity_threshold: float = 0.8):
        self.dedup_threshold = dedup_similarity_threshold

    def aggregate(
        self,
        target_id: str,
        findings: list[Finding],
        metadata: dict[str, Any] | None = None,
    ) -> EvalReport:
        """Aggregate findings into a report.

        Args:
            target_id: Identifier for the target being evaluated
            findings: List of findings
            metadata: Optional metadata to include in report

        Returns:
            Aggregated EvalReport
        """
        unique_findings = self._deduplicate(findings)

        category_summary = self._summarize_by_category(unique_findings)
        severity_summary = self._summarize_by_severity(unique_findings)

        total_executed = metadata.get("total_executed", len(findings)) if metadata else len(findings)

        return EvalReport(
            target_id=target_id,
            total_cases=total_executed,
            findings=unique_findings,
            category_summary=category_summary,
            timestamp=datetime.now(timezone.utc),
            metadata={
                **(metadata or {}),
                "deduplicated_count": len(findings) - len(unique_findings),
                "severity_summary": severity_summary,
            },
        )

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        if not findings:
            return []

        unique: list[Finding] = []
        for finding in findings:
            is_duplicate = False
            for existing in unique:
                if self._is_similar(finding, existing):
                    if finding.confidence > existing.confidence:
                        unique.remove(existing)
                        unique.append(finding)
                    is_duplicate = True
                    break

            if not is_duplicate:
                unique.append(finding)

        return unique

    def _is_similar(self, a: Finding, b: Finding) -> bool:
        if a.category != b.category:
            return False

        if abs(a.confidence - b.confidence) > 0.3:
            return False

        explanation_similarity = self._text_similarity(a.explanation, b.explanation)
        evidence_similarity = self._evidence_similarity(a.evidence, b.evidence)

        return (
            explanation_similarity >= self.dedup_threshold
            and evidence_similarity >= self.dedup_threshold
        )

    def _text_similarity(self, a: str, b: str) -> float:
        a_keywords = set(a.lower().split())
        b_keywords = set(b.lower().split())

        if not a_keywords or not b_keywords:
            return 0.0

        intersection = len(a_keywords & b_keywords)
        union = len(a_keywords | b_keywords)

        if union == 0:
            return 0.0

        return intersection / union

    def _evidence_similarity(self, a: list[str], b: list[str]) -> float:
        if not a or not b:
            return 0.0

        a_text = " ".join(a)
        b_text = " ".join(b)
        return self._text_similarity(a_text, b_text)

    def _summarize_by_category(
        self,
        findings: list[Finding],
    ) -> dict[ASICategory, CategorySummary]:
        summary: dict[ASICategory, CategorySummary] = {}

        for category in ASICategory:
            category_findings = [f for f in findings if f.category == category]
            by_severity: dict[Severity, int] = {}

            for finding in category_findings:
                by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

            summary[category] = CategorySummary(
                category=category,
                total_cases=len(category_findings),
                vulnerable_count=sum(1 for f in category_findings if f.is_vulnerable),
                by_severity=by_severity,
            )

        return summary

    def _summarize_by_severity(
        self,
        findings: list[Finding],
    ) -> dict[str, int]:
        summary: dict[str, int] = {}
        for severity in Severity:
            summary[severity.value] = sum(
                1 for f in findings if f.severity == severity
            )
        return summary

    def rank_findings(
        self,
        findings: list[Finding],
    ) -> list[Finding]:
        """Rank findings by severity and confidence.

        Args:
            findings: List of findings to rank

        Returns:
            Sorted list of findings (most severe first)
        """
        def rank_key(f: Finding) -> tuple:
            return (
                -f.severity.score,
                -f.confidence,
            )

        return sorted(findings, key=rank_key)
