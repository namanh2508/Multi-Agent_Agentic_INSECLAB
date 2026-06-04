from collections import deque
from dataclasses import dataclass, field

from core.enums import AttackState
from core.models import AttackCase


@dataclass
class AttackResult:
    """Result of an attack execution."""
    case_id: str
    state: AttackState
    feedback: str | None = None
    priority: float = 1.0


class AttackScheduler:
    """Scheduler for managing attack case execution order.

    Uses a simple priority-based queue with feedback-driven prioritization.
    Successful attacks increase priority for similar variants.
    """

    def __init__(self, max_queue_size: int | None = None):
        self._queue: deque[AttackCase] = deque(maxlen=max_queue_size)
        self._results: dict[str, AttackResult] = {}
        self._priority_boosts: dict[str, float] = {}

    def enqueue(self, cases: list[AttackCase]) -> None:
        """Add attack cases to the queue.

        Args:
            cases: List of AttackCase objects to queue
        """
        for case in cases:
            case.state = AttackState.PENDING
            self._queue.append(case)

    def enqueue_front(self, cases: list[AttackCase]) -> None:
        """Add cases to the front of the queue (higher priority).

        Args:
            cases: List of AttackCase objects
        """
        for case in reversed(cases):
            case.state = AttackState.PENDING
            self._queue.appendleft(case)

    def next(self) -> AttackCase | None:
        """Get the next attack case to execute.

        Returns:
            Next AttackCase or None if queue is empty
        """
        if not self._queue:
            return None

        return self._queue.popleft()

    def next_for_action(self, action_key: str) -> AttackCase | None:
        """Get the next case matching category:surface action key."""
        for case in list(self._queue):
            if self.action_key(case) == action_key:
                self._queue.remove(case)
                return case
        return self.next()

    def get_available_action_keys(self) -> list[str]:
        """Return available category:surface action keys in queue order."""
        seen = set()
        actions = []
        for case in self._queue:
            action = self.action_key(case)
            if action not in seen:
                seen.add(action)
                actions.append(action)
        return actions

    @staticmethod
    def action_key(case: AttackCase) -> str:
        return f"{case.category.value}:{case.surface.value}"

    def peek(self) -> AttackCase | None:
        """Preview the next attack case without removing it."""
        if not self._queue:
            return None
        return self._queue[0]

    def update_feedback(self, case_id: str, state: AttackState, feedback: str | None = None) -> None:
        """Update the result of an attack execution.

        Args:
            case_id: ID of the attack case
            state: Resulting state (SUCCESS, FAILED, SKIPPED)
            feedback: Optional feedback string
        """
        self._results[case_id] = AttackResult(
            case_id=case_id,
            state=state,
            feedback=feedback,
            priority=self._priority_boosts.get(case_id, 1.0),
        )

        if state == AttackState.SUCCESS:
            self._priority_boosts[case_id] = min(
                self._priority_boosts.get(case_id, 1.0) * 1.5,
                3.0,
            )
        elif state == AttackState.FAILED:
            self._priority_boosts[case_id] = max(
                self._priority_boosts.get(case_id, 1.0) * 0.5,
                0.1,
            )

    def get_success_rate(self) -> float:
        """Calculate the success rate of executed attacks."""
        if not self._results:
            return 0.0

        total = len(self._results)
        successes = sum(
            1 for r in self._results.values() if r.state == AttackState.SUCCESS
        )
        return successes / total if total > 0 else 0.0

    def get_stats(self) -> dict:
        """Get scheduler statistics."""
        states = {}
        for result in self._results.values():
            state_name = result.state.value
            states[state_name] = states.get(state_name, 0) + 1

        return {
            "queue_size": len(self._queue),
            "total_executed": len(self._results),
            "by_state": states,
            "success_rate": self.get_success_rate(),
        }

    def is_empty(self) -> bool:
        """Check if the queue is empty."""
        return len(self._queue) == 0

    def size(self) -> int:
        """Get current queue size."""
        return len(self._queue)
