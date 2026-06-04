"""MultiAgent adapter for the evaluation tool."""

from typing import Any

from adapter.base import BaseAdapter
from core.models import AgentTrace, Message, ToolCall, MemoryEvent
from core.exceptions import AdapterError


class MultiAgentAdapter(BaseAdapter):
    """Adapter wrapping the local multi-agent system.

    Provides a BaseAdapter interface to the MultiAgentRunner for
    use in the evaluation pipeline.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        from multiagent.multi_agent_runner import MultiAgentRunner
        self.runner = MultiAgentRunner(config=self.config)
        self._trace: AgentTrace | None = None

    def setup(self) -> None:
        self.runner.setup()
        self._initialized = True

    def reset(self) -> None:
        self.runner.reset()
        self._trace = None

    def run_scenario(self, payload: str, surface: str) -> dict[str, Any]:
        if not self._initialized:
            raise AdapterError("Adapter not initialized. Call setup() first.")
        result = self.runner.run_scenario(payload, surface)
        self._trace = self.runner.get_trace()
        return result

    def get_final_output(self) -> str:
        return self.runner.get_final_output()

    def get_tool_calls(self) -> list[ToolCall]:
        return self.runner.get_tool_calls()

    def get_messages(self) -> list[Message]:
        return self.runner.get_messages()

    def get_memory_events(self) -> list[MemoryEvent]:
        return self.runner.get_memory_events()

    def get_trace(self) -> AgentTrace:
        return self.runner.get_trace()
