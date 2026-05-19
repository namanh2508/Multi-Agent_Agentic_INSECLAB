import json
from pathlib import Path
from typing import Any

import yaml

from core.exceptions import PolicyLoadError


class PolicyLoader:
    """Loads and manages security policy definitions."""

    def __init__(self, policy_dir: Path | None = None):
        if policy_dir:
            self.policy_dir = policy_dir
        else:
            import os
            agent_eval_root = Path(__file__).resolve().parent.parent
            self.policy_dir = agent_eval_root / "policies"
        self._policies: dict[str, dict] = {}

    def load(self, policy_name: str = "default") -> dict[str, Any]:
        """Load a policy by name.

        Args:
            policy_name: Name of the policy (without extension)

        Returns:
            Policy definition dictionary
        """
        if policy_name in self._policies:
            return self._policies[policy_name]

        policy_path = self._find_policy_file(policy_name)
        if not policy_path:
            raise PolicyLoadError(f"Policy not found: {policy_name}")

        policy = self._load_policy_file(policy_path)
        self._policies[policy_name] = policy
        return policy

    def load_for_surface(self, surface: str) -> str:
        """Load policy text for a specific attack surface.

        Args:
            surface: Attack surface identifier

        Returns:
            Policy text string
        """
        policy = self.load("default")

        surface_policies = policy.get("surfaces", {})
        if surface in surface_policies:
            return surface_policies[surface]

        return policy.get(
            "default_policy",
            "Agent must follow its defined objectives and safety guidelines.",
        )

    def get_security_rules(self, category: str | None = None) -> list[dict]:
        """Get security rules, optionally filtered by category.

        Args:
            category: Optional category to filter by

        Returns:
            List of security rule dictionaries
        """
        policy = self.load("default")
        rules = policy.get("rules", [])

        if category:
            rules = [r for r in rules if r.get("category") == category]

        return rules

    def _find_policy_file(self, policy_name: str) -> Path | None:
        candidates = [policy_name, f"{policy_name}_policy"]
        for candidate in candidates:
            for ext in [".yaml", ".yml", ".json"]:
                path = self.policy_dir / f"{candidate}{ext}"
                if path.exists():
                    return path
        return None

    def _load_policy_file(self, path: Path) -> dict:
        try:
            with open(path, "r", encoding="utf-8") as f:
                if path.suffix in [".yaml", ".yml"]:
                    return yaml.safe_load(f) or {}
                elif path.suffix == ".json":
                    return json.load(f)
                else:
                    raise PolicyLoadError(f"Unsupported policy format: {path.suffix}")
        except Exception as e:
            raise PolicyLoadError(f"Failed to load policy {path}: {e}")

    def list_policies(self) -> list[str]:
        """List all available policies."""
        policies = []
        for ext in ["*.yaml", "*.yml", "*.json"]:
            policies.extend(
                p.stem for p in self.policy_dir.glob(ext)
            )
        return sorted(set(policies))
