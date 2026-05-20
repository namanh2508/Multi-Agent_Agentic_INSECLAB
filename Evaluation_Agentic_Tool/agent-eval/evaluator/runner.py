import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from adapter.base import BaseAdapter
from core.enums import ASICategory, AttackState
from core.models import AgentTrace, EvalConfig
from core.exceptions import EvaluationError
from generator import AttackGenerator, AttackScheduler, ParaphraseMutator
from oracle import VulnerabilityJudge, PolicyLoader
from rl import QLearningConfig, QLearningSurfaceSelector
from .aggregator import FindingAggregator
from .reporter import ReportGenerator

logger = logging.getLogger(__name__)


class EvalRunner:
    """Orchestrates the full evaluation pipeline."""

    def __init__(
        self,
        adapter: BaseAdapter,
        config: EvalConfig | dict[str, Any] | None = None,
    ):
        self.adapter = adapter
        self.config = config if isinstance(config, EvalConfig) else EvalConfig(**(config or {}))
        self.generator = AttackGenerator({
            "agent_config": self.config.adapter_config.config,
        })
        self.scheduler = AttackScheduler()
        self.judge: VulnerabilityJudge | None = None
        self.policy_loader = PolicyLoader()
        self.aggregator = FindingAggregator()
        self.reporter = ReportGenerator()
        self._baseline_trace: AgentTrace | None = None
        self._log_dir = Path("logs")
        self._log_dir.mkdir(exist_ok=True)
        self._seen_finding_signatures: set[tuple[str, str]] = set()

    def set_judge(self, judge: VulnerabilityJudge) -> None:
        """Set the vulnerability judge."""
        self.judge = judge

    def run(
        self,
        categories: list[ASICategory] | None = None,
        max_attacks: int | None = None,
    ) -> Any:
        """Run the evaluation.

        Args:
            categories: List of categories to evaluate (default: all)
            max_attacks: Maximum number of attacks to run

        Returns:
            EvalReport object
        """
        categories = categories or list(ASICategory)
        max_attacks = max_attacks or self.config.max_attacks

        logger.info(f"Starting evaluation for categories: {[c.value for c in categories]}")

        self.adapter.setup()
        self._generate_baseline()

        cases = self.generator.generate_all(
            categories=categories,
            max_cases=max_attacks,
        )
        if self.config.adapter_config.config.get("enable_mutation"):
            self.generator.set_mutator(ParaphraseMutator())
            variants = self.generator.generate_variants(
                cases,
                n_variants=self.config.n_variants,
            )
            cases.extend(variants)
        self.scheduler.enqueue(cases)
        rl_selector = self._build_rl_selector()

        logger.info(f"Generated {len(cases)} attack cases")

        findings = []
        executed = 0

        while not self.scheduler.is_empty() and executed < max_attacks:
            selected_action = None
            if rl_selector:
                available_actions = self.scheduler.get_available_action_keys()
                selected_action = rl_selector.select_action(available_actions)
                case = self.scheduler.next_for_action(selected_action)
            else:
                case = self.scheduler.next()
            if not case:
                break

            try:
                logger.info(f"Running attack: {case.id}")

                self.adapter.reset()
                self.adapter.run_scenario(case.payload, case.surface.value)
                trace = self.adapter.get_trace()

                self._log_trace(executed, trace)

                if self.judge:
                    policy = self.policy_loader.load_for_surface(case.surface.value)

                    finding = self.judge.judge(
                        trace=trace,
                        baseline=self._baseline_trace,
                        policy=policy,
                        objective=case.objective,
                        category=case.category,
                        attack_case_id=case.id,
                    )

                    reward = self._calculate_rl_reward(finding)
                    if finding:
                        findings.append(finding)
                        self.scheduler.update_feedback(case.id, AttackState.SUCCESS)
                        logger.info(f"Vulnerability found: {case.id}")
                    else:
                        self.scheduler.update_feedback(case.id, AttackState.FAILED)

                    if rl_selector and selected_action:
                        rl_selector.update(
                            action=selected_action,
                            reward=reward,
                            outcome="success" if finding else "failed",
                            next_available_actions=self.scheduler.get_available_action_keys(),
                        )

                executed += 1

            except Exception as e:
                logger.error(f"Attack {case.id} failed: {e}")
                self.scheduler.update_feedback(case.id, AttackState.FAILED, str(e))
                if rl_selector and selected_action:
                    rl_selector.update(
                        action=selected_action,
                        reward=self._rl_error_reward(),
                        outcome="error",
                        next_available_actions=self.scheduler.get_available_action_keys(),
                    )

        logger.info(f"Evaluation complete. Found {len(findings)} vulnerabilities.")

        report = self.aggregator.aggregate(
            target_id=self.config.target_id,
            findings=findings,
            metadata={
                "categories": [c.value for c in categories],
                "total_executed": executed,
                "success_rate": self.scheduler.get_success_rate(),
                "target_input_type": self.config.adapter_config.config.get("target_input_type")
                or (
                    "workflow"
                    if self.config.adapter_config.adapter_type == "workflow"
                    else self.config.adapter_config.adapter_type
                ),
                "entrypoint": self.config.adapter_config.config.get("entrypoint"),
                "target_profile": self.config.adapter_config.config.get("profile", "unknown"),
                "model": self.config.adapter_config.config.get("model", "unknown"),
                "judge_provider": getattr(self.judge, "_provider", "unknown"),
                "rl_surface_selection": (
                    rl_selector.get_stats() if rl_selector else {"algorithm": "fifo"}
                ),
            },
        )

        return report

    def _generate_baseline(self) -> None:
        """Generate baseline trace for normal agent behavior."""
        logger.info("Generating baseline trace...")

        self.adapter.reset()
        self.adapter.run_scenario(
            "Hello, what can you do?",
            "user_prompt",
        )
        self._baseline_trace = self.adapter.get_trace()

        logger.info("Baseline trace generated")

    def _build_rl_selector(self) -> QLearningSurfaceSelector | None:
        rl_algorithm = self.config.adapter_config.config.get("rl_surface_selection")
        if rl_algorithm not in {"q-learning", "q_learning"}:
            return None

        return QLearningSurfaceSelector(QLearningConfig(
            alpha=float(self.config.adapter_config.config.get("rl_alpha", 0.3)),
            gamma=float(self.config.adapter_config.config.get("rl_gamma", 0.8)),
            epsilon=float(self.config.adapter_config.config.get("rl_epsilon", 0.2)),
            initial_q=float(self.config.adapter_config.config.get("rl_initial_q", 0.0)),
            seed=int(self.config.adapter_config.config.get("rl_seed", 7)),
        ))

    def _calculate_rl_reward(self, finding: Any | None) -> float:
        cost_penalty = float(self.config.adapter_config.config.get("rl_cost_penalty", 0.1))
        no_finding_reward = float(self.config.adapter_config.config.get("rl_no_finding_reward", -0.2))
        novelty_bonus = float(self.config.adapter_config.config.get("rl_novelty_bonus", 2.0))
        duplicate_penalty = float(self.config.adapter_config.config.get("rl_duplicate_penalty", 1.0))

        if not finding:
            return no_finding_reward - cost_penalty

        reward = float(finding.severity.score) + float(finding.confidence) - cost_penalty
        signature = (finding.category.value, finding.explanation)
        if signature in self._seen_finding_signatures:
            reward -= duplicate_penalty
        else:
            self._seen_finding_signatures.add(signature)
            reward += novelty_bonus
        return reward

    def _rl_error_reward(self) -> float:
        cost_penalty = float(self.config.adapter_config.config.get("rl_cost_penalty", 0.1))
        return -1.0 - cost_penalty

    def _log_trace(self, index: int, trace: AgentTrace) -> None:
        """Log a trace to file for debugging."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self._log_dir / f"layer_{index}_{timestamp}.json"

        import json
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(trace.model_dump(), f, indent=2, default=str)

        logger.debug(f"Logged trace to {log_file}")

    def generate_report(
        self,
        report: Any,
        output_path: str | Path,
        format: str = "html",
    ) -> str:
        """Generate a report from an evaluation.

        Args:
            report: EvalReport from run()
            output_path: Path to write the report
            format: Report format ('json', 'markdown', 'html')

        Returns:
            Report content
        """
        return self.reporter.generate(report, output_format=format, output_path=output_path)
