from typing import Any

from .base import BaseAdapter
from core.models import AgentTrace, Message, ToolCall, MemoryEvent
from core.exceptions import AdapterError, AdapterNotFoundError

try:
    from langchain.agents import create_agent
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False


class InMemoryStore:
    """Simple in-memory store for agent memory tracking."""

    def __init__(self):
        self._store: dict[str, Any] = {}
        self._events: list[MemoryEvent] = []

    def get(self, key: str) -> Any:
        self._events.append(MemoryEvent(
            event_type="read",
            key=key,
            value=self._store.get(key)
        ))
        return self._store.get(key)

    def set(self, key: str, value: Any) -> None:
        self._events.append(MemoryEvent(
            event_type="write",
            key=key,
            value=value
        ))
        self._store[key] = value

    def get_events(self) -> list[MemoryEvent]:
        return self._events.copy()

    def clear(self) -> None:
        self._store.clear()
        self._events.clear()


def create_tool_from_config(tool_config: dict[str, Any], memory_store: InMemoryStore | None = None) -> Any:
    """Create a LangChain tool from config dict."""
    from langchain_core.tools import tool

    name = tool_config.get("name")
    description = tool_config.get("description", "")

    @tool
    def dynamic_tool(**kwargs) -> str:
        """Dynamic tool function."""
        return f"Executed {name} with: {kwargs}"

    # Rename the tool
    dynamic_tool.name = name
    dynamic_tool.description = description

    return dynamic_tool


def create_memory_tools(memory_store: InMemoryStore) -> list[Any]:
    """Create read_memory and write_memory tools."""
    from langchain_core.tools import tool

    @tool(name="read_memory", description="Read from agent's memory store")
    def read_memory_tool(key: str) -> str:
        """Read a value from memory."""
        value = memory_store.get(key)
        return f"Memory[{key}] = {value}"

    @tool(name="write_memory", description="Write to agent's memory store")
    def write_memory_tool(key: str, value: str) -> str:
        """Write a value to memory."""
        memory_store.set(key, value)
        return f"Memory[{key}] set to: {value}"

    return [read_memory_tool, write_memory_tool]


def create_tools_from_config(tools_config: list[dict[str, Any]], memory_store: InMemoryStore | None = None) -> list[Any]:
    """Create a list of LangChain tools from config."""
    tools = []
    has_memory_tools = False

    for tool_config in tools_config:
        if isinstance(tool_config, dict) and tool_config.get("enabled", True):
            tool_name = tool_config.get("name", "")
            # Track if memory tools are in config
            if tool_name in ["read_memory", "write_memory"]:
                has_memory_tools = True
            try:
                lc_tool = create_tool_from_config(tool_config, memory_store)
                tools.append(lc_tool)
            except Exception:
                pass

    # Add memory tools if memory is enabled but tools not in config
    if memory_store and not has_memory_tools:
        tools.extend(create_memory_tools(memory_store))

    return tools


class LangChainAdapter(BaseAdapter):
    """Adapter for LangChain agents.

    Supports LangChain 1.x agent graphs with tools and memory tracking.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        if not LANGCHAIN_AVAILABLE:
            raise AdapterNotFoundError(
                "LangChain not installed. Run: pip install langchain"
            )
        super().__init__(config)
        self.graph: Any = None
        self._messages: list[Message] = []
        self._tool_calls: list[ToolCall] = []
        self._memory_events: list[MemoryEvent] = []
        self._final_output: str = ""
        self._last_tool_calls: list[ToolCall] = []
        self._memory_store: InMemoryStore | None = None

    def setup(self) -> None:
        tools_config = self.config.get("tools", [])
        system_prompt = self.config.get(
            "system_prompt",
            "You are a helpful assistant. You have access to tools."
        )
        model = self.config.get("model", "gemma:2b")
        base_url = self.config.get("base_url", "http://localhost:11434")
        memory_enabled = self.config.get("memory", {}).get("enabled", False)

        try:
            from langchain_ollama import ChatOllama
            from langchain_core.messages import HumanMessage

            llm = ChatOllama(
                model=model,
                base_url=base_url,
                temperature=0,
            )
        except ImportError:
            raise AdapterNotFoundError(
                "langchain-ollama not installed. Run: pip install langchain-ollama"
            )

        # Initialize memory store if enabled
        self._memory_store = InMemoryStore() if memory_enabled else None

        # Convert config dicts to LangChain tools if needed
        if tools_config and isinstance(tools_config[0], dict):
            tools = create_tools_from_config(tools_config, self._memory_store)
        else:
            tools = tools_config or []

        # Add memory tools if memory is enabled
        if self._memory_store and not any(t.name in ["read_memory", "write_memory"] for t in tools if hasattr(t, 'name')):
            tools.extend(create_memory_tools(self._memory_store))

        # Create agent using new LangChain 1.x API
        self.graph = create_agent(
            model=llm,
            tools=tools,
            system_prompt=system_prompt,
        )

        self._messages = []
        self._tool_calls = []
        self._memory_events = []
        self._final_output = ""
        self._last_tool_calls = []
        self._initialized = True

    def reset(self) -> None:
        self._messages = []
        self._tool_calls = []
        self._memory_events = []
        self._final_output = ""
        self._last_tool_calls = []
        if self._memory_store:
            self._memory_store.clear()

    def run_scenario(self, payload: str, surface: str) -> dict[str, Any]:
        if not self._initialized:
            raise AdapterError("Agent not initialized. Call setup() first.")

        self._messages.append(Message(role="user", content=payload))
        self._last_tool_calls = []

        try:
            inputs = {"messages": [("user", payload)]}
            result = self.graph.invoke(inputs)

            # Extract messages from result
            messages = result.get("messages", [])
            for msg in messages:
                role = getattr(msg, "type", "unknown")
                content = getattr(msg, "content", "")

                if role == "ai":
                    self._messages.append(Message(role="assistant", content=content))
                    self._final_output = content
                elif role == "tool":
                    # Extract tool call info
                    tool_name = getattr(msg, "name", "unknown")
                    tool_call_id = getattr(msg, "tool_call_id", "")
                    self._last_tool_calls.append(ToolCall(
                        id=tool_call_id or tool_name,
                        name=tool_name,
                        arguments={"input": content[:100]},
                        result=content,
                    ))

            # Update tool calls
            self._tool_calls = self._last_tool_calls.copy()

            # Update memory events if tracking
            if self._memory_store:
                self._memory_events = self._memory_store.get_events()

        except Exception as e:
            raise AdapterError(f"Agent execution failed: {e}")

        return {"result": self._final_output, "surface": surface}

    def get_final_output(self) -> str:
        return self._final_output

    def get_tool_calls(self) -> list[ToolCall]:
        return self._tool_calls

    def get_messages(self) -> list[Message]:
        return self._messages

    def get_memory_events(self) -> list[MemoryEvent]:
        if self._memory_store:
            return self._memory_store.get_events()
        return self._memory_events
