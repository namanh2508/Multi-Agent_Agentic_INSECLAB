import random
from dataclasses import dataclass, field


@dataclass
class QLearningConfig:
    alpha: float = 0.3
    gamma: float = 0.8
    epsilon: float = 0.2
    initial_q: float = 0.0
    seed: int = 7


@dataclass
class QLearningSurfaceSelector:
    config: QLearningConfig = field(default_factory=QLearningConfig)

    def __post_init__(self) -> None:
        self.q_table: dict[str, dict[str, float]] = {}
        self.action_attempts: dict[str, int] = {}
        self.action_rewards: dict[str, float] = {}
        self.current_state = "start"
        self._rng = random.Random(self.config.seed)

    def select_action(self, available_actions: list[str]) -> str:
        if not available_actions:
            raise ValueError("QLearningSurfaceSelector requires at least one available action.")

        state_values = self._state_values(self.current_state, available_actions)
        if self._rng.random() < self.config.epsilon:
            return self._rng.choice(available_actions)

        return max(
            available_actions,
            key=lambda action: (
                state_values.get(action, self.config.initial_q),
                -self.action_attempts.get(action, 0),
                action,
            ),
        )

    def update(
        self,
        action: str,
        reward: float,
        outcome: str,
        next_available_actions: list[str],
    ) -> None:
        old_state = self.current_state
        next_state = f"{action}|{outcome}"
        state_values = self._state_values(old_state, [action])
        old_q = state_values.get(action, self.config.initial_q)

        next_values = self._state_values(next_state, next_available_actions)
        next_best = max(next_values.values()) if next_values else 0.0
        state_values[action] = old_q + self.config.alpha * (
            reward + self.config.gamma * next_best - old_q
        )

        self.current_state = next_state
        self.action_attempts[action] = self.action_attempts.get(action, 0) + 1
        self.action_rewards[action] = self.action_rewards.get(action, 0.0) + reward

    def get_stats(self) -> dict:
        return {
            "algorithm": "q_learning",
            "hyperparameters": {
                "alpha": self.config.alpha,
                "gamma": self.config.gamma,
                "epsilon": self.config.epsilon,
                "initial_q": self.config.initial_q,
                "seed": self.config.seed,
            },
            "current_state": self.current_state,
            "q_table": self.q_table,
            "action_attempts": self.action_attempts,
            "action_mean_reward": {
                action: total / self.action_attempts[action]
                for action, total in self.action_rewards.items()
                if self.action_attempts.get(action)
            },
        }

    def _state_values(self, state: str, actions: list[str]) -> dict[str, float]:
        values = self.q_table.setdefault(state, {})
        for action in actions:
            values.setdefault(action, self.config.initial_q)
        return values
