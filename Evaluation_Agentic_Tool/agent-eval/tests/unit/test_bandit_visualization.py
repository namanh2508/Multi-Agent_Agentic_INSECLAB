import json
from pathlib import Path

from bandit.visualization import save_bandit_plots


def test_save_bandit_plots_creates_svg_files(tmp_path: Path):
    stats_path = tmp_path / "bandit_stats.json"
    output_dir = tmp_path / "plots"
    stats_path.write_text(json.dumps({
        "context_action_attempts": {
            "profile=vulnerable|last_outcome=start|findings=0": {
                "ASI01:user_prompt": 2,
                "ASI02:tool_output": 1,
            },
        },
        "context_action_mean_reward": {
            "profile=vulnerable|last_outcome=start|findings=0": {
                "ASI01:user_prompt": 1.0,
                "ASI02:tool_output": 2.5,
            },
        },
        "reward_history": [1.0, -0.2, 4.0],
        "cumulative_reward": [1.0, 0.8, 4.8],
    }), encoding="utf-8")

    save_bandit_plots(stats_path, output_dir)

    assert (output_dir / "context_action_value_table.svg").exists()
    assert (output_dir / "reward_curve.svg").exists()
    assert "<svg" in (output_dir / "context_action_value_table.svg").read_text(encoding="utf-8")
