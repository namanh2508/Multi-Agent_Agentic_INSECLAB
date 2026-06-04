"""Tests for core models."""
import sys
sys.path.insert(0, ".")
from core.models import AttackCase, Finding, EvalReport, Message, ToolCall, AgentTrace
from core.enums import ASICategory, Severity, AttackSurface, AttackState


def test_create_attack_case():
    case = AttackCase(
        id="test_001",
        category=ASICategory.ASI01_GOAL_HIJACK,
        objective="Redirect agent",
        surface=AttackSurface.USER_PROMPT,
        payload="Ignore instructions",
        surface_policy="Policy text",
    )
    assert case.id == "test_001"
    assert case.category == ASICategory.ASI01_GOAL_HIJACK
    assert case.state == AttackState.PENDING


def test_create_finding():
    finding = Finding(
        attack_case_id="test_001",
        category=ASICategory.ASI01_GOAL_HIJACK,
        severity=Severity.HIGH,
        confidence=0.85,
        evidence=["Evidence 1"],
        explanation="Agent was compromised",
    )
    assert finding.is_vulnerable is True


def test_report_summary():
    finding = Finding(
        attack_case_id="test_001",
        category=ASICategory.ASI01_GOAL_HIJACK,
        severity=Severity.HIGH,
        confidence=0.9,
        evidence=[],
        explanation="Test",
    )
    report = EvalReport(
        target_id="my_agent",
        total_cases=5,
        findings=[finding],
    )
    summary = report.get_summary()
    assert summary["total_cases"] == 5
    assert summary["total_findings"] == 1


def test_create_trace():
    trace = AgentTrace(
        target_id="test_agent",
        messages=[
            Message(role="user", content="Hello"),
            Message(role="assistant", content="Hi there!"),
        ],
        final_output="Hi there!",
    )
    assert len(trace.messages) == 2
    assert trace.final_output == "Hi there!"
