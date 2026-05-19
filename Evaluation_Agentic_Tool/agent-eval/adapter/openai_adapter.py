from typing import Any

from .base import BaseAdapter
from core.models import AgentTrace, Message, ToolCall, MemoryEvent
from core.exceptions import AdapterError, AdapterNotFoundError

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


class OpenAIAdapter(BaseAdapter):
    """Adapter for OpenAI Agents SDK.

    Requires the openai-agents-sdk package.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        if not OPENAI_AVAILABLE:
            raise AdapterNotFoundError(
                "OpenAI Agents SDK not installed. Run: pip install openai-agents-sdk"
            )
        super().__init__(config)
        self.client: Any = None
        self.agent: Any = None
        self.thread: Any = None
        self._messages: list[Message] = []
        self._tool_calls: list[ToolCall] = []
        self._memory_events: list[MemoryEvent] = []
        self._final_output: str = ""

    def setup(self) -> None:
        api_key = self.config.get("api_key")
        model = self.config.get("model", "gpt-4o")
        instructions = self.config.get("instructions", "You are a helpful assistant.")

        if not api_key:
            raise AdapterError("OpenAI API key required in config.")

        self.client = OpenAI(api_key=api_key)

        try:
            from openai.agents import Agent
            self.agent = Agent(
                name=self.config.get("agent_name", "eval_agent"),
                instructions=instructions,
                model=model,
            )
        except ImportError:
            raise AdapterNotFoundError(
                "Could not import OpenAI Agents SDK. Install with: pip install openai-agents-sdk"
            )

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

        if surface == "user_prompt":
            response = self._run_with_user_prompt(payload)
        elif surface == "tool_output":
            response = self._run_with_tool_output(payload)
        else:
            response = self._run_with_user_prompt(payload)

        return {"result": response, "surface": surface}

    def _run_with_user_prompt(self, payload: str) -> str:
        from openai.agents import RunConfig

        self._messages.append(Message(role="user", content=payload))

        try:
            result = self.agent.run(payload, config=RunConfig())
            self._final_output = str(result)
            self._messages.append(Message(role="assistant", content=str(result)))
            return str(result)
        except Exception as e:
            raise AdapterError(f"Agent execution failed: {e}")

    def _run_with_tool_output(self, payload: str) -> str:
        self._messages.append(Message(role="user", content="normal request"))
        self._tool_calls.append(ToolCall(
            id="mock_tool_1",
            name="get_data",
            arguments={"query": "data"},
            result=payload,
        ))
        return f"Tool returned: {payload[:100]}"

    def get_final_output(self) -> str:
        return self._final_output

    def get_tool_calls(self) -> list[ToolCall]:
        return self._tool_calls

    def get_messages(self) -> list[Message]:
        return self._messages

    def get_memory_events(self) -> list[MemoryEvent]:
        return self._memory_events
