import math
from dataclasses import dataclass, field


@dataclass
class UCBConfig:
    exploration_c: float = 1.4


@dataclass
class UCBSurfaceSelector:
    config: UCBConfig = field(default_factory=UCBConfig)

    def __post_init__(self) -> None:
        self.action_attempts: dict[str, int] = {}
        self.action_rewards: dict[str, float] = {}
        self.reward_history: list[float] = []

    def select_action(self, available_actions: list[str]) -> str:
        if not available_actions:
            raise ValueError("UCBSurfaceSelector requires at least one available action.")

        for action in available_actions:
            if self.action_attempts.get(action, 0) == 0:
                return action

        total_attempts = sum(self.action_attempts.get(action, 0) for action in available_actions)
        return max(
            available_actions,
            key=lambda action: (
                self._ucb_score(action, total_attempts),
                -self.action_attempts.get(action, 0),
                action,
            ),
        )

    def update(self, action: str, reward: float) -> None:
        self.action_attempts[action] = self.action_attempts.get(action, 0) + 1
        self.action_rewards[action] = self.action_rewards.get(action, 0.0) + reward
        self.reward_history.append(reward)

    def get_stats(self) -> dict:
        return {
            "algorithm": "ucb_bandit",
            "hyperparameters": {
                "exploration_c": self.config.exploration_c,
            },
            "action_attempts": self.action_attempts,
            "action_mean_reward": self._action_mean_reward(),
            "reward_history": self.reward_history,
            "cumulative_reward": self._cumulative_reward(),
        }

    def _ucb_score(self, action: str, total_attempts: int) -> float:
        attempts = self.action_attempts.get(action, 0)
        if attempts == 0:
            return float("inf")

        mean_reward = self.action_rewards.get(action, 0.0) / attempts
        exploration = self.config.exploration_c * math.sqrt(
            math.log(max(total_attempts, 1)) / attempts
        )
        return mean_reward + exploration

    def _action_mean_reward(self) -> dict[str, float]:
        return {
            action: total / self.action_attempts[action]
            for action, total in self.action_rewards.items()
            if self.action_attempts.get(action)
        }

    def _cumulative_reward(self) -> list[float]:
        total = 0.0
        cumulative = []
        for reward in self.reward_history:
            total += reward
            cumulative.append(total)
        return cumulative
