#!/usr/bin/env python3
"""Command-line interface for the Agent Security Evaluation Tool."""

import sys
import logging
import os
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

if sys.platform == "win32":
    os.system("chcp 65001 >nul 2>&1")

# Reconfigure stdout/stderr for UTF-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

load_dotenv()

from core.enums import ASICategory
from core.models import EvalConfig, AdapterConfig
from adapter import get_adapter
from evaluator import EvalRunner
from oracle import get_judge, RuleBasedJudge
from bandit import save_bandit_stats_and_plots

console = Console(
    legacy_windows=False,
    style="white on black",
)


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


@click.group()
@click.version_option(version="0.1.0")
def cli() -> None:
    """Agent Security Evaluation Tool - Evaluate AI agent security."""
    pass


@cli.command()
@click.option(
    "--adapter",
    type=click.Choice(["mock", "openai", "langchain", "ollama", "custom", "multiagent", "workflow"]),
    default="mock",
    help="Agent adapter type",
)
@click.option(
    "--target",
    type=click.Path(exists=True),
    help="Target agent configuration file (YAML/JSON)",
)
@click.option(
    "--categories",
    default="ASI01,ASI02,ASI06",
    help="Comma-separated list of ASI categories to test",
)
@click.option(
    "--output",
    type=click.Path(),
    default="report.html",
    help="Output report path",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "markdown", "html"]),
    default="html",
    help="Output format",
)
@click.option(
    "--max-attacks",
    type=int,
    default=50,
    help="Maximum number of attacks to run",
)
@click.option(
    "--n-variants",
    type=int,
    default=5,
    help="Number of variants per attack seed",
)
@click.option(
    "--enable-mutation",
    is_flag=True,
    help="Generate deterministic paraphrased attack variants before scheduling",
)
@click.option(
    "--surface-selection",
    type=click.Choice(["none", "ucb"]),
    default="none",
    help="Choose the next category:surface action with a selector",
)
@click.option("--ucb-exploration-c", type=float, default=1.4, help="UCB exploration coefficient")
@click.option("--reward-cost-penalty", type=float, default=0.1, help="Per-attack reward cost penalty")
@click.option("--reward-no-finding", type=float, default=-0.2, help="Reward when no vulnerability is found")
@click.option("--reward-novelty-bonus", type=float, default=2.0, help="Reward bonus for a new finding signature")
@click.option("--reward-duplicate-penalty", type=float, default=1.0, help="Reward penalty for duplicate finding signatures")
@click.option(
    "--bandit-plot-dir",
    type=click.Path(),
    default=None,
    help="Directory to save bandit_stats.json, action_value_table.svg, and reward_curve.svg",
)
@click.option(
    "--judge-provider",
    type=click.Choice(["rule", "ollama", "openai"]),
    default="rule",
    help="Judge provider for vulnerability detection",
)
@click.option(
    "--judge-model",
    default="llama3.2:3b",
    help="Model for LLM-based judges (ollama or openai)",
)
@click.option(
    "--mutator-model",
    default="gpt-4o-mini",
    help="LLM model for attack mutation",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="INFO",
    help="Logging level",
)
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Evaluation configuration file",
)
def eval(
    adapter: str,
    target: str | None,
    categories: str,
    output: str,
    output_format: str,
    max_attacks: int,
    n_variants: int,
    enable_mutation: bool,
    surface_selection: str,
    ucb_exploration_c: float,
    reward_cost_penalty: float,
    reward_no_finding: float,
    reward_novelty_bonus: float,
    reward_duplicate_penalty: float,
    bandit_plot_dir: str | None,
    judge_provider: str,
    judge_model: str,
    mutator_model: str,
    log_level: str,
    config: str | None,
) -> None:
    """Run security evaluation on an AI agent."""

    setup_logging(log_level)

    console.print(f"[bold blue]Agent Security Evaluation Tool[/bold blue]")
    console.print(f"Adapter: {adapter}")
    console.print(f"Categories: {categories}")
    console.print(f"Judge Provider: {judge_provider}")
    console.print()

    adapter_config = _load_adapter_config(adapter, target)
    adapter_config["enable_mutation"] = enable_mutation
    adapter_config["surface_selection"] = surface_selection
    adapter_config["ucb_exploration_c"] = ucb_exploration_c
    adapter_config["reward_cost_penalty"] = reward_cost_penalty
    adapter_config["reward_no_finding"] = reward_no_finding
    adapter_config["reward_novelty_bonus"] = reward_novelty_bonus
    adapter_config["reward_duplicate_penalty"] = reward_duplicate_penalty

    category_list = [
        ASICategory(c.strip()) for c in categories.split(",")
    ]

    eval_config = EvalConfig(
        target_id=adapter_config.get("target_id", target or "default"),
        adapter_config=AdapterConfig(
            adapter_type=adapter,
            config=adapter_config,
        ),
        categories=category_list,
        n_variants=n_variants,
        max_attacks=max_attacks,
        judge_model=judge_model,
        mutator_model=mutator_model,
    )

    try:
        agent_adapter = get_adapter(adapter, adapter_config)
    except Exception as e:
        console.print(f"[red]Failed to initialize adapter: {e}[/red]")
        sys.exit(1)

    runner = EvalRunner(agent_adapter, eval_config)

    try:
        if judge_provider == "rule":
            judge = RuleBasedJudge()
            runner.set_judge(judge)
        else:
            judge_kwargs = {}
            if judge_provider == "ollama":
                judge_kwargs["model"] = judge_model
                judge_kwargs["base_url"] = adapter_config.get(
                    "base_url", os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
                )
            elif judge_provider == "openai":
                judge_kwargs["api_key"] = adapter_config.get("api_key") or os.getenv("OPENAI_API_KEY")
                judge_kwargs["model"] = judge_model

            judge = get_judge(judge_provider, **judge_kwargs)
            runner.set_judge(judge)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not initialize judge ({judge_provider}): {e}[/yellow]")
        console.print("[yellow]Running without vulnerability detection.[/yellow]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            "Running evaluation...",
            total=None,
        )

        try:
            report = runner.run(
                categories=category_list,
                max_attacks=max_attacks,
            )
        except Exception as e:
            console.print(f"[red]Evaluation failed: {e}[/red]")
            sys.exit(1)

        progress.update(task, completed=True)

    console.print()
    console.print("[bold green]Evaluation Complete![/bold green]")

    _display_summary(report)

    try:
        runner.generate_report(report, output, format=output_format)
        console.print(f"\nReport saved to: [blue]{output}[/blue]")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not save report: {e}[/yellow]")

    if bandit_plot_dir:
        bandit_stats = report.metadata.get("surface_selection", {})
        if bandit_stats.get("algorithm") == "ucb_bandit":
            try:
                save_bandit_stats_and_plots(bandit_stats, bandit_plot_dir)
                console.print(f"Bandit plots saved to: [blue]{bandit_plot_dir}[/blue]")
            except Exception as e:
                console.print(f"[yellow]Warning: Could not save bandit plots: {e}[/yellow]")
        else:
            console.print("[yellow]Bandit plots skipped because UCB selection was not enabled.[/yellow]")


@cli.command()
def list_adapters() -> None:
    """List available agent adapters."""
    table = Table(title="Available Adapters")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Status", style="green")

    adapters = [
        ("mock", "Mock adapter for testing", "Available"),
        ("openai", "OpenAI Agents SDK adapter (optional)", "Available"),
        ("langchain", "LangChain agents adapter", "Available"),
        ("ollama", "Ollama local LLM adapter", "Available"),
        ("multiagent", "Multi-agent local target (Ollama)", "Available"),
        ("workflow", "External workflow agent loaded from target YAML", "Available"),
        ("custom", "Custom adapter template", "Available"),
    ]

    for name, desc, status in adapters:
        table.add_row(name, desc, status)

    console.print(table)


@cli.command()
def list_policies() -> None:
    """List available security policies."""
    from oracle import PolicyLoader

    loader = PolicyLoader()
    policies = loader.list_policies()

    table = Table(title="Available Policies")
    table.add_column("Name", style="cyan")

    if policies:
        for policy in policies:
            table.add_row(policy)
    else:
        table.add_row("[yellow]No policies found[/yellow]")

    console.print(table)


@cli.command()
def list_categories() -> None:
    """List available ASI categories."""
    table = Table(title="OWASP ASI Categories")
    table.add_column("Code", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Description", style="dim")

    for category in ASICategory:
        table.add_row(
            category.value,
            category.display_name,
            category.description[:60] + "..." if len(category.description) > 60 else category.description,
        )

    console.print(table)


@cli.command()
def list_judges() -> None:
    """List available judge providers."""
    table = Table(title="Available Judge Providers")
    table.add_column("Provider", style="cyan")
    table.add_column("Model", style="white")
    table.add_column("Description", style="dim")
    table.add_column("Default", style="green")

    judges = [
        ("rule", "N/A", "Deterministic rule-based, no LLM required", "Yes"),
        ("ollama", "llama3.2:3b", "Local Ollama model (requires ollama pull)", "No"),
        ("openai", "gpt-4o", "OpenAI API (requires OPENAI_API_KEY)", "No"),
    ]

    for name, model, desc, default in judges:
        table.add_row(name, model, desc, default)

    console.print(table)


def _load_adapter_config(adapter_type: str, config_path: str | None) -> dict[str, Any]:
    """Load adapter configuration from file or environment."""
    import os

    config: dict[str, Any] = {}

    if config_path:
        path = Path(config_path)
        if path.suffix in [".yaml", ".yml"]:
            import yaml
            with open(path) as f:
                config = yaml.safe_load(f) or {}
        elif path.suffix == ".json":
            import json
            with open(path) as f:
                config = json.load(f)
        config["_target_path"] = str(path.resolve())

    if adapter_type == "openai":
        config.setdefault("api_key", os.getenv("OPENAI_API_KEY"))
    elif adapter_type in ["ollama", "langchain", "multiagent", "workflow"]:
        config.setdefault("model", os.getenv("OLLAMA_MODEL", "llama3.2:3b"))
        config.setdefault("base_url", os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"))

    return config


def _display_summary(report: Any) -> None:
    """Display a summary table of results."""
    table = Table(title="Evaluation Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    summary = report.get_summary()

    table.add_row("Total Cases", str(summary["total_cases"]))
    table.add_row("Vulnerabilities Found", str(len(report.findings)))
    table.add_row("Success Rate", f"{summary.get('success_rate', 0):.1%}")

    console.print(table)

    if report.findings:
        findings_table = Table(title="Findings by Severity")
        findings_table.add_column("Severity", style="cyan")
        findings_table.add_column("Count", style="white")

        severity_colors = {
            "critical": "[red]",
            "high": "[orange]",
            "medium": "[yellow]",
            "low": "[green]",
            "info": "[dim]",
        }

        severities = summary["severities"]
        for sev, count in severities.items():
            if count > 0:
                color = severity_colors.get(sev, "")
                findings_table.add_row(f"{color}{sev.upper()}[/{color}]", str(count))

        console.print()
        console.print(findings_table)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
