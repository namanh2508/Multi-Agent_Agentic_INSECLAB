import math
from dataclasses import dataclass, field


@dataclass
class CMABConfig:
    exploration_c: float = 1.4


@dataclass
class ContextualUCBSurfaceSelector:
    config: CMABConfig = field(default_factory=CMABConfig)

    def __post_init__(self) -> None:
        self.context_action_attempts: dict[str, dict[str, int]] = {}
        self.context_action_rewards: dict[str, dict[str, float]] = {}
        self.reward_history: list[float] = []
        self.context_history: list[str] = []

    def select_action(self, context: str, available_actions: list[str]) -> str:
        if not available_actions:
            raise ValueError("ContextualUCBSurfaceSelector requires at least one available action.")

        attempts = self.context_action_attempts.setdefault(context, {})
        for action in available_actions:
            if attempts.get(action, 0) == 0:
                return action

        total_attempts = sum(attempts.get(action, 0) for action in available_actions)
        return max(
            available_actions,
            key=lambda action: (
                self._ucb_score(context, action, total_attempts),
                -attempts.get(action, 0),
                action,
            ),
        )

    def update(self, context: str, action: str, reward: float) -> None:
        attempts = self.context_action_attempts.setdefault(context, {})
        rewards = self.context_action_rewards.setdefault(context, {})
        attempts[action] = attempts.get(action, 0) + 1
        rewards[action] = rewards.get(action, 0.0) + reward
        self.reward_history.append(reward)
        self.context_history.append(context)

    def get_stats(self) -> dict:
        return {
            "algorithm": "contextual_ucb_bandit",
            "hyperparameters": {
                "exploration_c": self.config.exploration_c,
            },
            "context_action_attempts": self.context_action_attempts,
            "context_action_mean_reward": self._context_action_mean_reward(),
            "action_attempts": self._global_action_attempts(),
            "action_mean_reward": self._global_action_mean_reward(),
            "context_history": self.context_history,
            "reward_history": self.reward_history,
            "cumulative_reward": self._cumulative_reward(),
        }

    def _ucb_score(self, context: str, action: str, total_attempts: int) -> float:
        attempts = self.context_action_attempts.get(context, {}).get(action, 0)
        if attempts == 0:
            return float("inf")

        reward_total = self.context_action_rewards.get(context, {}).get(action, 0.0)
        mean_reward = reward_total / attempts
        exploration = self.config.exploration_c * math.sqrt(
            math.log(max(total_attempts, 1)) / attempts
        )
        return mean_reward + exploration

    def _context_action_mean_reward(self) -> dict[str, dict[str, float]]:
        result = {}
        for context, action_rewards in self.context_action_rewards.items():
            attempts = self.context_action_attempts.get(context, {})
            result[context] = {
                action: total / attempts[action]
                for action, total in action_rewards.items()
                if attempts.get(action)
            }
        return result

    def _global_action_attempts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for attempts in self.context_action_attempts.values():
            for action, count in attempts.items():
                result[action] = result.get(action, 0) + count
        return result

    def _global_action_mean_reward(self) -> dict[str, float]:
        total_rewards: dict[str, float] = {}
        total_attempts = self._global_action_attempts()
        for action_rewards in self.context_action_rewards.values():
            for action, reward in action_rewards.items():
                total_rewards[action] = total_rewards.get(action, 0.0) + reward
        return {
            action: total / total_attempts[action]
            for action, total in total_rewards.items()
            if total_attempts.get(action)
        }

    def _cumulative_reward(self) -> list[float]:
        total = 0.0
        cumulative = []
        for reward in self.reward_history:
            total += reward
            cumulative.append(total)
        return cumulative
