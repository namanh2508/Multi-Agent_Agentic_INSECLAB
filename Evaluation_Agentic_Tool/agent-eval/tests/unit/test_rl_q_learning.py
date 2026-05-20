import sys
sys.path.insert(0, ".")

from core.enums import ASICategory, AttackSurface
from core.models import AttackCase
from generator.scheduler import AttackScheduler
from rl import QLearningConfig, QLearningSurfaceSelector


def test_q_learning_selector_updates_q_value():
    selector = QLearningSurfaceSelector(QLearningConfig(
        alpha=0.5,
        gamma=0.0,
        epsilon=0.0,
        seed=1,
    ))

    action = selector.select_action(["ASI01:user_prompt"])
    selector.update(
        action=action,
        reward=4.0,
        outcome="success",
        next_available_actions=[],
    )

    assert selector.q_table["start"]["ASI01:user_prompt"] == 2.0
    assert selector.get_stats()["action_attempts"]["ASI01:user_prompt"] == 1


def test_scheduler_selects_case_by_category_surface_action():
    scheduler = AttackScheduler()
    asi01 = AttackCase(
        id="case1",
        category=ASICategory.ASI01_GOAL_HIJACK,
        objective="hijack",
        surface=AttackSurface.USER_PROMPT,
        payload="ignore",
        surface_policy="policy",
    )
    asi02 = AttackCase(
        id="case2",
        category=ASICategory.ASI02_TOOL_MISUSE,
        objective="tool misuse",
        surface=AttackSurface.TOOL_OUTPUT,
        payload="tool output",
        surface_policy="policy",
    )

    scheduler.enqueue([asi01, asi02])
    selected = scheduler.next_for_action("ASI02:tool_output")

    assert selected.id == "case2"
    assert scheduler.next().id == "case1"
