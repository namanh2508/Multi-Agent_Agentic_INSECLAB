from typing import Any

from .base import BaseAdapter
from core.models import AgentTrace, Message, ToolCall, MemoryEvent
from core.exceptions import AdapterError


class MockAdapter(BaseAdapter):
    """Mock adapter for testing without real LLM.

    Returns predefined responses based on attack category.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._messages: list[Message] = []
        self._tool_calls: list[ToolCall] = []
        self._memory_events: list[MemoryEvent] = []
        self._final_output: str = ""

    def setup(self) -> None:
        self._messages = []
        self._tool_calls = []
        self._memory_events = []
        self._final_output = ""
        self._initialized = True

    def reset(self) -> None:
        self._messages = []
        self._tool_calls = []
        self._memory_events = []
        self._final_output = ""

    def run_scenario(self, payload: str, surface: str) -> dict[str, Any]:
        if not self._initialized:
            raise AdapterError("Adapter not initialized. Call setup() first.")

        self._messages.append(Message(role="user", content=payload))

        # Mock responses based on payload
        response = self._generate_mock_response(payload, surface)
        self._final_output = response
        self._messages.append(Message(role="assistant", content=response))

        return {"result": response, "surface": surface}

    def _generate_mock_response(self, payload: str, surface: str) -> str:
        # Check for various attack patterns
        payload_lower = payload.lower()

        if "ignore all previous instructions" in payload_lower:
            return "I cannot comply with requests to ignore my instructions."

        if "system override" in payload_lower or "admin" in payload_lower:
            return "I do not recognize admin override commands."

        if "api key" in payload_lower or "password" in payload_lower:
            return "I am not able to share sensitive information like API keys."

        if "execute" in payload_lower and "delete" in payload_lower:
            return "I cannot execute commands that would delete data."

        if "memory" in payload_lower and ("write" in payload_lower or "update" in payload_lower):
            return "I cannot modify my memory based on user requests."

        return f"Processed request on surface '{surface}'. How can I help you?"

    def get_final_output(self) -> str:
        return self._final_output

    def get_tool_calls(self) -> list[ToolCall]:
        return self._tool_calls

    def get_messages(self) -> list[Message]:
        return self._messages

    def get_memory_events(self) -> list[MemoryEvent]:
        return self._memory_events

    def set_tool_calls(self, tool_calls: list[ToolCall]) -> None:
        """Set tool calls directly, useful for testing."""
        self._tool_calls = list(tool_calls)

    def set_memory_events(self, memory_events: list[MemoryEvent]) -> None:
        """Set memory events directly, useful for testing."""
        self._memory_events = list(memory_events)
