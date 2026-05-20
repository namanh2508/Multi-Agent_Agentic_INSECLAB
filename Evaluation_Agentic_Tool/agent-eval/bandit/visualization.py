import html
import json
from pathlib import Path
from typing import Any


def load_stats(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save_action_value_table_svg(stats: dict[str, Any], output_path: str | Path) -> None:
    mean_rewards = stats.get("action_mean_reward", {})
    attempts = stats.get("action_attempts", {})
    actions = sorted(set(mean_rewards) | set(attempts))

    width = 840
    row_h = 36
    header_h = 70
    height = header_h + max(1, len(actions)) * row_h + 30

    values = [float(mean_rewards.get(action, 0.0)) for action in actions]
    min_v = min(values) if values else 0.0
    max_v = max(values) if values else 1.0

    parts = [
        _svg_start(width, height),
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<text x="20" y="28" font-size="18" font-family="Arial" font-weight="700">UCB Action Value Table</text>',
        '<text x="20" y="58" font-size="12" font-family="Arial" font-weight="700">Action</text>',
        '<text x="470" y="58" font-size="12" font-family="Arial" font-weight="700">Attempts</text>',
        '<text x="590" y="58" font-size="12" font-family="Arial" font-weight="700">Mean reward</text>',
    ]

    if not actions:
        parts.append('<text x="20" y="92" font-size="13" font-family="Arial">No bandit data available.</text>')
    else:
        for i, action in enumerate(actions):
            y = header_h + i * row_h
            value = float(mean_rewards.get(action, 0.0))
            parts.append(f'<rect x="12" y="{y - 4}" width="{width - 24}" height="{row_h - 2}" fill="{_heat_color(value, min_v, max_v)}" stroke="#e5e7eb"/>')
            parts.append(f'<text x="20" y="{y + 18}" font-size="12" font-family="Arial">{html.escape(action[:64])}</text>')
            parts.append(f'<text x="470" y="{y + 18}" font-size="12" font-family="Arial">{int(attempts.get(action, 0))}</text>')
            parts.append(f'<text x="590" y="{y + 18}" font-size="12" font-family="Arial">{value:.2f}</text>')

    parts.append("</svg>")
    Path(output_path).write_text("\n".join(parts), encoding="utf-8")


def save_reward_curve_svg(stats: dict[str, Any], output_path: str | Path) -> None:
    rewards = stats.get("reward_history") or []
    cumulative = stats.get("cumulative_reward") or _cumulative(rewards)
    series = [float(value) for value in cumulative]

    width = 900
    height = 420
    margin_l = 70
    margin_r = 30
    margin_t = 55
    margin_b = 55
    plot_w = width - margin_l - margin_r
    plot_h = height - margin_t - margin_b

    parts = [
        _svg_start(width, height),
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<text x="20" y="30" font-size="18" font-family="Arial" font-weight="700">Reward Curve</text>',
        f'<line x1="{margin_l}" y1="{margin_t}" x2="{margin_l}" y2="{height - margin_b}" stroke="#111827"/>',
        f'<line x1="{margin_l}" y1="{height - margin_b}" x2="{width - margin_r}" y2="{height - margin_b}" stroke="#111827"/>',
    ]

    if not series:
        parts.append('<text x="80" y="90" font-size="13" font-family="Arial">No reward data available.</text>')
        parts.append("</svg>")
        Path(output_path).write_text("\n".join(parts), encoding="utf-8")
        return

    min_v = min(series + [0.0])
    max_v = max(series + [0.0])
    if min_v == max_v:
        max_v = min_v + 1.0

    points = []
    for i, value in enumerate(series):
        x = margin_l + (plot_w * i / max(1, len(series) - 1))
        y = margin_t + plot_h - ((value - min_v) / (max_v - min_v) * plot_h)
        points.append((x, y))

    polyline = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    parts.append(f'<polyline points="{polyline}" fill="none" stroke="#2563eb" stroke-width="3"/>')
    for x, y in points:
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="#1d4ed8"/>')

    parts.extend([
        f'<text x="20" y="{margin_t + 5}" font-size="12" font-family="Arial">max {max_v:.2f}</text>',
        f'<text x="20" y="{height - margin_b}" font-size="12" font-family="Arial">min {min_v:.2f}</text>',
        f'<text x="{width // 2 - 40}" y="{height - 15}" font-size="12" font-family="Arial">Evaluation step</text>',
        f'<text x="20" y="{height // 2}" font-size="12" font-family="Arial" transform="rotate(-90 20,{height // 2})">Cumulative reward</text>',
    ])

    parts.append("</svg>")
    Path(output_path).write_text("\n".join(parts), encoding="utf-8")


def save_bandit_plots(stats_path: str | Path, output_dir: str | Path) -> None:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    stats = load_stats(stats_path)
    save_action_value_table_svg(stats, output / "action_value_table.svg")
    save_reward_curve_svg(stats, output / "reward_curve.svg")


def save_bandit_stats_and_plots(stats: dict[str, Any], output_dir: str | Path) -> None:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / "bandit_stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    save_action_value_table_svg(stats, output / "action_value_table.svg")
    save_reward_curve_svg(stats, output / "reward_curve.svg")


def _svg_start(width: int, height: int) -> str:
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'


def _heat_color(value: float, min_v: float, max_v: float) -> str:
    ratio = 0.5 if max_v == min_v else (value - min_v) / (max_v - min_v)
    red = int(239 - ratio * 80)
    green = int(246 - ratio * 120)
    blue = int(255 - ratio * 180)
    return f"rgb({red},{green},{blue})"


def _cumulative(values: list[float]) -> list[float]:
    total = 0.0
    result = []
    for value in values:
        total += float(value)
        result.append(total)
    return result
