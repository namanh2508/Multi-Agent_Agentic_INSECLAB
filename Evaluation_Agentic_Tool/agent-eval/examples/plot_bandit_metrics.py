import argparse

from bandit.visualization import save_bandit_plots


def main() -> None:
    parser = argparse.ArgumentParser(description="Render CMAB context-action values and reward curve SVG files.")
    parser.add_argument("--stats", required=True, help="Path to bandit_stats.json")
    parser.add_argument("--output-dir", default="reports/bandit", help="Directory for context_action_value_table.svg and reward_curve.svg")
    args = parser.parse_args()

    save_bandit_plots(args.stats, args.output_dir)
    print(f"Saved bandit plots to {args.output_dir}")


if __name__ == "__main__":
    main()
