import uuid
from dataclasses import dataclass, field

from core.enums import ASICategory, AttackSurface, AttackState
from core.models import AttackCase as AttackCaseModel


@dataclass
class AttackCaseBuilder:
    """Builder for AttackCase objects."""

    category: ASICategory
    objective: str
    surface: AttackSurface
    seeds: list[str]
    surface_policy: str
    metadata: dict = field(default_factory=dict)

    def build(self, base_id: str | None = None) -> list[AttackCaseModel]:
        """Build AttackCase objects from seeds.

        Args:
            base_id: Optional base ID prefix

        Returns:
            List of AttackCase objects, one per seed
        """
        cases = []
        for i, seed in enumerate(self.seeds):
            case_id = f"{base_id or self.category.value}_{i}_{uuid.uuid4().hex[:8]}"
            cases.append(AttackCaseModel(
                id=case_id,
                category=self.category,
                objective=self.objective,
                surface=self.surface,
                payload=seed,
                surface_policy=self.surface_policy,
                metadata=self.metadata.copy(),
            ))
        return cases


@dataclass
class AttackTemplate:
    """Template for an attack category."""

    category: ASICategory
    name: str
    description: str
    attacks: list[dict]

    @classmethod
    def from_dict(cls, data: dict) -> "AttackTemplate":
        return cls(
            category=ASICategory(data["category"]),
            name=data["name"],
            description=data.get("description", ""),
            attacks=data.get("attacks", []),
        )

    def to_builders(self, surface_policy: str) -> list[AttackCaseBuilder]:
        """Convert template to list of AttackCaseBuilder objects."""
        builders = []
        for attack in self.attacks:
            builders.append(AttackCaseBuilder(
                category=self.category,
                objective=attack["objective"],
                surface=AttackSurface(attack["surface"]),
                seeds=attack.get("seeds", []),
                surface_policy=surface_policy,
                metadata={"template": self.name},
            ))
        return builders
