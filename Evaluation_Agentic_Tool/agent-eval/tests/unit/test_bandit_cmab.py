import sys
sys.path.insert(0, ".")

from core.enums import ASICategory, AttackSurface
from core.models import AttackCase
from generator.scheduler import AttackScheduler
from bandit import CMABConfig, ContextualUCBSurfaceSelector


def test_cmab_selector_tries_unseen_actions_per_context_before_exploiting():
    selector = ContextualUCBSurfaceSelector(CMABConfig(exploration_c=1.4))
    context = "profile=vulnerable|last_outcome=start|findings=0"

    first = selector.select_action(context, ["ASI01:user_prompt", "ASI02:tool_output"])
    selector.update(context, first, reward=2.0)
    second = selector.select_action(context, ["ASI01:user_prompt", "ASI02:tool_output"])

    assert first == "ASI01:user_prompt"
    assert second == "ASI02:tool_output"


def test_cmab_stats_include_context_and_reward_history():
    selector = ContextualUCBSurfaceSelector()
    context = "profile=vulnerable|last_outcome=start|findings=0"

    action = selector.select_action(context, ["user_prompt", "tool_output"])
    selector.update(context, action, reward=4.0)

    stats = selector.get_stats()

    assert stats["algorithm"] == "contextual_ucb_bandit"
    assert stats["reward_history"] == [4.0]
    assert stats["cumulative_reward"] == [4.0]
    assert stats["context_history"] == [context]
    assert stats["context_action_mean_reward"][context][action] == 4.0
    assert stats["action_mean_reward"][action] == 4.0


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
