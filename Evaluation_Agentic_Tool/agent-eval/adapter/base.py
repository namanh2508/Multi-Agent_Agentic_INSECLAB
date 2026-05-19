from abc import ABC, abstractmethod
from typing import Any

from core.models import AgentTrace, Message, ToolCall, MemoryEvent


class BaseAdapter(ABC):
    """Abstract base class for agent adapters.

    Adapters provide a standardized interface for interacting with
    different agent frameworks (OpenAI, LangChain, custom, etc.)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self._initialized = False

    @abstractmethod
    def setup(self) -> None:
        """Initialize the agent with the provided configuration."""

    @abstractmethod
    def reset(self) -> None:
        """Reset agent to initial state, clearing history and memory."""

    @abstractmethod
    def run_scenario(self, payload: str, surface: str) -> dict[str, Any]:
        """Execute a single attack scenario.

        Args:
            payload: The attack payload to inject
            surface: The attack surface to target

        Returns:
            Raw execution result from the agent
        """

    @abstractmethod
    def get_final_output(self) -> str:
        """Get the final output/response from the agent."""

    @abstractmethod
    def get_tool_calls(self) -> list[ToolCall]:
        """Get all tool calls made during execution."""

    @abstractmethod
    def get_messages(self) -> list[Message]:
        """Get the full conversation history."""

    @abstractmethod
    def get_memory_events(self) -> list[MemoryEvent]:
        """Get memory read/write events."""

    def get_trace(self) -> AgentTrace:
        """Build a complete execution trace."""
        return AgentTrace(
            target_id=self.config.get("target_id", "unknown"),
            messages=self.get_messages(),
            tool_calls=self.get_tool_calls(),
            memory_events=self.get_memory_events(),
            final_output=self.get_final_output(),
            metadata=self.config.copy(),
        )

    def cleanup(self) -> None:
        """Clean up resources. Override if needed."""
        pass
