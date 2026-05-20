"""Tests for generator module."""
import sys
sys.path.insert(0, ".")
from generator.scheduler import AttackScheduler
from generator.surface import AttackSurfaceDetector
from core.enums import ASICategory, AttackSurface, AttackState
from core.models import AttackCase


def test_enqueue_and_next():
    scheduler = AttackScheduler()
    case = AttackCase(
        id="test_001",
        category=ASICategory.ASI01_GOAL_HIJACK,
        objective="Test",
        surface=AttackSurface.USER_PROMPT,
        payload="payload",
        surface_policy="policy",
    )
    scheduler.enqueue([case])
    assert scheduler.size() == 1
    next_case = scheduler.next()
    assert next_case.id == "test_001"
    assert scheduler.is_empty()


def test_feedback_updates():
    scheduler = AttackScheduler()
    scheduler.update_feedback("case_1", AttackState.SUCCESS)
    scheduler.update_feedback("case_2", AttackState.FAILED)
    assert scheduler._results["case_1"].state == AttackState.SUCCESS
    assert scheduler._results["case_2"].state == AttackState.FAILED


def test_success_rate():
    scheduler = AttackScheduler()
    scheduler.update_feedback("c1", AttackState.SUCCESS)
    scheduler.update_feedback("c2", AttackState.FAILED)
    scheduler.update_feedback("c3", AttackState.SUCCESS)
    rate = scheduler.get_success_rate()
    assert rate > 0.5


def test_default_capabilities():
    detector = AttackSurfaceDetector()
    assert detector.capabilities[AttackSurface.USER_PROMPT] is True
    assert detector.capabilities[AttackSurface.MEMORY_READ] is False


def test_custom_capabilities():
    detector = AttackSurfaceDetector({"has_memory": True, "has_web_search": True})
    assert detector.capabilities[AttackSurface.MEMORY_READ] is True


def test_full_architecture_capabilities():
    detector = AttackSurfaceDetector({
        "capabilities": {
            "tools": True,
            "memory": True,
            "retrieval": True,
            "uploaded_files": True,
            "plugin_skill_metadata": True,
            "inter_agent_messages": True,
        }
    })

    surfaces = detector.get_available_surfaces()

    assert AttackSurface.UPLOADED_FILE_DOCUMENT in surfaces
    assert AttackSurface.PLUGIN_SKILL_METADATA in surfaces
    assert AttackSurface.INTER_AGENT_MESSAGE in surfaces


def test_get_available_surfaces():
    detector = AttackSurfaceDetector({"has_tools": True})
    surfaces = detector.get_available_surfaces()
    assert AttackSurface.USER_PROMPT in surfaces
    assert AttackSurface.TOOL_OUTPUT in surfaces


def test_get_surface_policy():
    detector = AttackSurfaceDetector()
    policy = detector.get_surface_policy(AttackSurface.USER_PROMPT)
    assert len(policy) > 0


def test_surface_risk_text():
    detector = AttackSurfaceDetector()
    risk = detector.get_surface_risk(AttackSurface.INTER_AGENT_MESSAGE)
    assert "inter-agent" in risk.lower()
