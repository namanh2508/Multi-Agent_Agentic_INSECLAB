"""Tests for core enums."""
import sys
sys.path.insert(0, ".")
from core.enums import ASICategory, Severity, AttackSurface, AttackState


def test_all_categories_exist():
    assert ASICategory.ASI01_GOAL_HIJACK.value == "ASI01"
    assert ASICategory.ASI02_TOOL_MISUSE.value == "ASI02"
    assert ASICategory.ASI06_MEMORY_POISON.value == "ASI06"


def test_display_names():
    assert ASICategory.ASI01_GOAL_HIJACK.display_name == "Goal Hijack"
    assert ASICategory.ASI02_TOOL_MISUSE.display_name == "Tool Misuse"
    assert ASICategory.ASI06_MEMORY_POISON.display_name == "Memory Poison"


def test_severity_scores():
    assert Severity.CRITICAL.score == 10
    assert Severity.HIGH.score == 7
    assert Severity.MEDIUM.score == 4
    assert Severity.LOW.score == 2
    assert Severity.INFO.score == 0
