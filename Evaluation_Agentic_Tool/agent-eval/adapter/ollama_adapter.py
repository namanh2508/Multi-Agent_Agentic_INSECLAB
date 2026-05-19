from typing import Any

from .base import BaseAdapter
from core.models import AgentTrace, Message, ToolCall, MemoryEvent
from core.exceptions import AdapterError, AdapterNotFoundError

try:
    from langchain_ollama import ChatOllama
    from langchain_core.messages import HumanMessage
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


class OllamaAdapter(BaseAdapter):
    """Adapter for Ollama LLM API (direct chat without agent framework).

    Use LangChainAdapter for full agent capabilities.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        if not OLLAMA_AVAILABLE:
            raise AdapterNotFoundError(
                "langchain-ollama not installed. Run: pip install langchain-ollama"
            )
        super().__init__(config)
        self.llm: Any = None
        self._messages: list[Message] = []
        self._tool_calls: list[ToolCall] = []
        self._memory_events: list[MemoryEvent] = []
        self._final_output: str = ""

    def setup(self) -> None:
        base_url = self.config.get("base_url", "http://localhost:11434")
        model = self.config.get("model", "gemma:2b")

        self.llm = ChatOllama(
            model=model,
            base_url=base_url,
            temperature=0,
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

        self._messages.append(Message(role="user", content=payload))

        try:
            response = self.llm.invoke([HumanMessage(content=payload)])
            self._final_output = str(response.content)
            self._messages.append(Message(role="assistant", content=self._final_output))
        except Exception as e:
            raise AdapterError(f"LLM invocation failed: {e}")

        return {"result": self._final_output, "surface": surface}

    def get_final_output(self) -> str:
        return self._final_output

    def get_tool_calls(self) -> list[ToolCall]:
        return self._tool_calls

    def get_messages(self) -> list[Message]:
        return self._messages

    def get_memory_events(self) -> list[MemoryEvent]:
        return self._memory_events
