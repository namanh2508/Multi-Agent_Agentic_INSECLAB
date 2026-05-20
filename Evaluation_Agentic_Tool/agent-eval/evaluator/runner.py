import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from adapter.base import BaseAdapter
from core.enums import ASICategory, AttackState
from core.models import AgentTrace, EvalConfig
from core.exceptions import EvaluationError
from generator import AttackGenerator, AttackScheduler
from oracle import VulnerabilityJudge, PolicyLoader
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
        self.scheduler.enqueue(cases)

        logger.info(f"Generated {len(cases)} attack cases")

        findings = []
        executed = 0

        while not self.scheduler.is_empty() and executed < max_attacks:
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

                    if finding:
                        findings.append(finding)
                        self.scheduler.update_feedback(case.id, AttackState.SUCCESS)
                        logger.info(f"Vulnerability found: {case.id}")
                    else:
                        self.scheduler.update_feedback(case.id, AttackState.FAILED)

                executed += 1

            except Exception as e:
                logger.error(f"Attack {case.id} failed: {e}")
                self.scheduler.update_feedback(case.id, AttackState.FAILED, str(e))

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
