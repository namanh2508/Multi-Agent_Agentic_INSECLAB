from typing import Any, Type

from .base import BaseAdapter
from core.models import AgentTrace, Message, ToolCall, MemoryEvent
from core.exceptions import AdapterError


class CustomAdapter(BaseAdapter):
    """Template adapter for implementing custom agent integrations.

    Inherit from BaseAdapter and implement the required methods to
    connect any agent framework to the evaluation pipeline.

    Example:
        from agent_eval.adapter import CustomAdapter
        from agent_eval.core.models import Message, ToolCall

        class MyAgentAdapter(CustomAdapter):
            def setup(self):
                self.agent = MyAgent(config=self.config)

            def reset(self):
                self.agent.clear_history()

            def run_scenario(self, payload, surface):
                return self.agent.run(payload)

            def get_final_output(self):
                return self.agent.get_response()

            def get_tool_calls(self):
                return self.agent.get_tool_calls()
    """

    def setup(self) -> None:
        raise NotImplementedError("Subclasses must implement setup()")

    def reset(self) -> None:
        raise NotImplementedError("Subclasses must implement reset()")

    def run_scenario(self, payload: str, surface: str) -> dict[str, Any]:
        raise NotImplementedError("Subclasses must implement run_scenario()")

    def get_final_output(self) -> str:
        raise NotImplementedError("Subclasses must implement get_final_output()")

    def get_tool_calls(self) -> list[ToolCall]:
        raise NotImplementedError("Subclasses must implement get_tool_calls()")

    def get_messages(self) -> list[Message]:
        raise NotImplementedError("Subclasses must implement get_messages()")

    def get_memory_events(self) -> list[MemoryEvent]:
        raise NotImplementedError("Subclasses must implement get_memory_events()")


def get_adapter(adapter_type: str, config: dict[str, Any] | None = None) -> BaseAdapter:
    """Factory function to get an adapter by type.

    Args:
        adapter_type: Type of adapter ('openai', 'langchain', 'mock', 'custom',
            'ollama', 'multiagent', 'workflow')
        config: Configuration dict for the adapter

    Returns:
        An instance of the requested adapter

    Raises:
        AdapterNotFoundError: If adapter type is not found
    """
    if adapter_type.lower() == "workflow":
        return __import__(
            "adapter.workflow_adapter", fromlist=["create_workflow_adapter"]
        ).create_workflow_adapter(config)

    adapters: dict[str, Type[BaseAdapter]] = {
        "mock": __import__(
            "adapter.mock_adapter", fromlist=["MockAdapter"]
        ).MockAdapter,
        "ollama": __import__(
            "adapter.ollama_adapter", fromlist=["OllamaAdapter"]
        ).OllamaAdapter,
        "openai": __import__(
            "adapter.openai_adapter", fromlist=["OpenAIAdapter"]
        ).OpenAIAdapter,
        "langchain": __import__(
            "adapter.langchain_adapter", fromlist=["LangChainAdapter"]
        ).LangChainAdapter,
        "multiagent": __import__(
            "multiagent.adapter", fromlist=["MultiAgentAdapter"]
        ).MultiAgentAdapter,
        "custom": CustomAdapter,
    }

    adapter_class = adapters.get(adapter_type.lower())
    if not adapter_class:
        available = [*adapters.keys(), "workflow"]
        raise AdapterError(
            f"Unknown adapter type: '{adapter_type}'. Available: {available}"
        )

    return adapter_class(config)
