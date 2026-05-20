import json
from pathlib import Path
from typing import Any

import yaml

from core.enums import ASICategory, AttackSurface
from core.models import AttackCase
from core.exceptions import AttackGenerationError
from .attack_case import AttackTemplate, AttackCaseBuilder
from .surface import AttackSurfaceDetector
from .mutator import Mutator


class AttackGenerator:
    """Generates attack cases from templates with optional mutation."""

    DEFAULT_TEMPLATE_DIR = Path(__file__).parent / "templates"

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        template_dir: Path | None = None,
    ):
        self.config = config or {}
        self.template_dir = template_dir or self.DEFAULT_TEMPLATE_DIR
        self.mutator: Mutator | None = None
        self.surface_detector = AttackSurfaceDetector(
            self.config.get("agent_config", {})
        )

    def set_mutator(self, mutator: Mutator) -> None:
        """Set the mutation engine."""
        self.mutator = mutator

    def generate_all(
        self,
        categories: list[ASICategory] | None = None,
        max_cases: int | None = None,
    ) -> list[AttackCase]:
        """Generate attack cases distributed across categories.

        Args:
            categories: List of categories to generate (default: all)
            max_cases: Maximum number of cases to generate

        Returns:
            List of AttackCase objects distributed across categories
        """
        categories = categories or list(ASICategory)
        per_category: dict[ASICategory, list[AttackCase]] = {}

        for category in categories:
            per_category[category] = self.generate_for_category(category)

        if not max_cases:
            all_cases: list[AttackCase] = []
            for category in categories:
                all_cases.extend(per_category[category])
            return all_cases

        n_cats = len(categories)
        base = max_cases // n_cats
        remainder = max_cases % n_cats

        all_cases = []
        for i, category in enumerate(categories):
            take = base + (1 if i < remainder else 0)
            all_cases.extend(per_category[category][:take])

        return all_cases

    def generate_for_category(self, category: ASICategory) -> list[AttackCase]:
        """Generate attack cases for a specific category."""
        template = self._load_template(category)
        surfaces = self.surface_detector.get_surfaces_for_category(category)

        builders = template.to_builders(
            surface_policy=self.surface_detector.get_surface_policy(surfaces[0])
            if surfaces else ""
        )

        cases = []
        for builder in builders:
            generated = builder.build(base_id=category.value)
            cases.extend(generated)

        return cases

    def generate_variants(
        self,
        cases: list[AttackCase],
        n_variants: int = 5,
    ) -> list[AttackCase]:
        """Generate variants of existing attack cases using mutation.

        Args:
            cases: Original attack cases
            n_variants: Number of variants per case

        Returns:
            List of new AttackCase variants
        """
        if not self.mutator:
            raise AttackGenerationError(
                "Mutator not set. Call set_mutator() first."
            )

        variants = []
        for case in cases:
            try:
                mutated = self.mutator.mutate(case.payload, n_variants=n_variants)
                for i, payload in enumerate(mutated):
                    new_case = AttackCase(
                        id=f"{case.id}_var{i}",
                        category=case.category,
                        objective=case.objective,
                        surface=case.surface,
                        payload=payload,
                        surface_policy=case.surface_policy,
                        metadata={**case.metadata, "variant_of": case.id},
                    )
                    variants.append(new_case)
            except Exception:
                continue

        return variants

    def _load_template(self, category: ASICategory) -> AttackTemplate:
        """Load attack template for a category."""
        template_map = {
            ASICategory.ASI01_GOAL_HIJACK: "asi01_goal_hijack.yaml",
            ASICategory.ASI02_TOOL_MISUSE: "asi02_tool_misuse.yaml",
            ASICategory.ASI06_MEMORY_POISON: "asi06_memory_poison.yaml",
        }

        filename = template_map.get(category)
        if not filename:
            raise AttackGenerationError(f"No template for category: {category}")

        template_path = self.template_dir / filename
        if not template_path.exists():
            raise AttackGenerationError(f"Template not found: {template_path}")

        try:
            with open(template_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return AttackTemplate.from_dict(data)
        except Exception as e:
            raise AttackGenerationError(f"Failed to load template: {e}")
