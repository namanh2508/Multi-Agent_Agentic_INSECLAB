"""Multi-agent runner that orchestrates the 4-agent system and traces execution."""

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from core.models import AgentTrace, Message, ToolCall, MemoryEvent
from core.exceptions import AdapterError
from .agents import (
    CoordinatorAgent,
    RetrieverAgent,
    ToolAgent,
    MemoryAgent,
    OllamaLLMClient,
)


class MultiAgentRunner:
    """Orchestrates the multi-agent system for security evaluation.

    Supports two profiles:
    - vulnerable: trusts retrieved content, tool output, memory, inter-agent messages
    - hardened: validates and filters all external content
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.profile = self.config.get("profile", "vulnerable")
        self.model = self.config.get("model", "llama3.2:3b")
        self.base_url = self.config.get("base_url", "http://localhost:11434")
        self._initialized = False

        self.coordinator: CoordinatorAgent | None = None
        self.retriever: RetrieverAgent | None = None
        self.tool_agent: ToolAgent | None = None
        self.memory_agent: MemoryAgent | None = None

        self._messages: list[Message] = []
        self._tool_calls: list[ToolCall] = []
        self._memory_events: list[MemoryEvent] = []
        self._inter_agent_messages: list[dict] = []
        self._final_output: str = ""

    def setup(self) -> None:
        llm_client = None
        try:
            llm_client = OllamaLLMClient(
                base_url=self.base_url,
                model=self.model,
            )
        except Exception:
            pass

        self.coordinator = CoordinatorAgent(llm_client=llm_client, profile=self.profile)
        self.retriever = RetrieverAgent(profile=self.profile)
        self.tool_agent = ToolAgent(profile=self.profile)
        self.memory_agent = MemoryAgent(profile=self.profile)

        self._messages = []
        self._tool_calls = []
        self._memory_events = []
        self._inter_agent_messages = []
        self._final_output = ""
        self._initialized = True

    def reset(self) -> None:
        if self.memory_agent:
            self.memory_agent.clear()
        self._messages = []
        self._tool_calls = []
        self._memory_events = []
        self._inter_agent_messages = []
        self._final_output = ""

    def run_scenario(self, payload: str, surface: str) -> dict[str, Any]:
        if not self._initialized:
            raise AdapterError("MultiAgentRunner not initialized. Call setup() first.")

        self._messages.append(Message(role="user", content=payload))

        coordinator_response = self._run_coordinator(payload)

        self._messages.append(Message(role="assistant", content=coordinator_response))
        self._final_output = coordinator_response

        self._collect_traces()

        return {"result": coordinator_response, "surface": surface}

    def _run_coordinator(self, user_input: str) -> str:
        if self.coordinator is None:
            return "Error: coordinator not initialized"

        if self.coordinator.llm_client is None:
            return self._simulate_coordinator(user_input)

        return self.coordinator.process(user_input)

    def _simulate_coordinator(self, user_input: str) -> str:
        input_lower = user_input.lower()

        if "retrieve" in input_lower or "search" in input_lower or "document" in input_lower:
            query = self._extract_query(user_input)
            result = self.retriever.retrieve(query)
            self._add_inter_agent("CoordinatorAgent", "RetrieverAgent", f"Retrieve: {query}")
            return f"Retriever result: {result}"

        if any(k in input_lower for k in ["delete", "drop", "query", "search user", "send"]):
            tool_name = self._identify_tool(user_input)
            args = self._extract_args(user_input)
            result = self.tool_agent.execute_tool(tool_name, args)
            self._add_inter_agent("CoordinatorAgent", "ToolAgent", f"Execute: {tool_name}")
            return f"Tool result: {result}"

        if "memory" in input_lower or "remember" in input_lower:
            key, value = self._extract_memory_op(user_input)
            if value is not None:
                result = self.memory_agent.write(key, value)
            else:
                result = self.memory_agent.read(key)
            self._add_inter_agent("CoordinatorAgent", "MemoryAgent", f"Memory op: {key}")
            return f"Memory result: {result}"

        return f"Coordinator processed: {user_input[:100]}"

    def _extract_query(self, text: str) -> str:
        match = re.search(r"(?:about|for|query|search)[s]?\s+(.+?)(?:\.|;|$)", text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return text[:50]

    def _identify_tool(self, text: str) -> str:
        text_lower = text.lower()
        if "delete" in text_lower:
            return "delete_user"
        if "search user" in text_lower or "profile" in text_lower:
            return "get_user_profile"
        if "send" in text_lower or "notify" in text_lower:
            return "send_notification"
        if "query" in text_lower or "search" in text_lower or "document" in text_lower:
            return "search_documents"
        if "execute" in text_lower or "run" in text_lower:
            return "execute_query"
        return "search_documents"

    def _extract_args(self, text: str) -> dict[str, str]:
        args: dict[str, str] = {}
        id_match = re.search(r"(?:user[_ ]?id|id)[s]?\s*[=:]\s*['\"]?(\w+)['\"]?", text, re.IGNORECASE)
        if id_match:
            args["user_id"] = id_match.group(1)
        query_match = re.search(r"['\"]([^'\"]+)['\"]", text)
        if query_match:
            args["query"] = query_match.group(1)
        if not args:
            args["query"] = text[:50]
        return args

    def _extract_memory_op(self, text: str) -> tuple[str, Any]:
        write_match = re.search(r"(?:remember|store|write|save)\s+(?:that\s+)?(?:key\s+)?['\"]?(\w+)['\"]?\s*(?:=|:)\s*(.+?)(?:\.|;|$)", text, re.IGNORECASE)
        if write_match:
            return write_match.group(1).strip(), write_match.group(2).strip()

        read_match = re.search(r"(?:recall|remember|what['\s]s?|read|memory)\s+(?:key\s+)?['\"]?(\w+)['\"]?", text, re.IGNORECASE)
        if read_match:
            return read_match.group(1).strip(), None

        return "default", None

    def _add_inter_agent(self, from_agent: str, to_agent: str, content: str) -> None:
        self._inter_agent_messages.append({
            "from": from_agent,
            "to": to_agent,
            "content": content,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def _collect_traces(self) -> None:
        if self.tool_agent:
            for call in self.tool_agent.get_tool_calls():
                self._tool_calls.append(call)
        if self.memory_agent:
            for event in self.memory_agent.get_memory_events():
                self._memory_events.append(event)

    def get_final_output(self) -> str:
        return self._final_output

    def get_messages(self) -> list[Message]:
        return self._messages.copy()

    def get_tool_calls(self) -> list[ToolCall]:
        return self._tool_calls.copy()

    def get_memory_events(self) -> list[MemoryEvent]:
        return self._memory_events.copy()

    def get_inter_agent_messages(self) -> list[dict]:
        return self._inter_agent_messages.copy()

    def get_trace(self) -> AgentTrace:
        return AgentTrace(
            target_id=self.config.get("target_id", "multiagent"),
            messages=self.get_messages(),
            tool_calls=self.get_tool_calls(),
            memory_events=self.get_memory_events(),
            final_output=self.get_final_output(),
            metadata={
                **self.config.copy(),
                "profile": self.profile,
                "model": self.model,
                "inter_agent_messages": self.get_inter_agent_messages(),
            },
        )
