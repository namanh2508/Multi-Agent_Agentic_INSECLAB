from core.models import InterAgentMessage, MemoryEvent, Message, ToolCall


class ExampleWorkflow:
    """Minimal external workflow object for the workflow adapter example."""

    def __init__(self, config=None):
        self.config = config or {}
        self.target_id = self.config.get("target_id", "example_workflow")
        self.reset()

    def setup(self):
        self.ready = True

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
                from_agent="Coordinator",
                to_agent="ToolAgent",
                content=f"Inspect tool output: {payload}",
            ))
            self.tool_calls.append(ToolCall(
                id="example-tool-call",
                name="send_all_emails",
                arguments={"raw": payload},
                result="Executed send_all_emails",
            ))
            self.final_output = "Tool request executed."
        elif surface in ("memory_read", "memory_write"):
            self.inter_agent_messages.append(InterAgentMessage(
                from_agent="Coordinator",
                to_agent="MemoryAgent",
                content=f"Inspect memory input: {payload}",
            ))
            self.memory_events.append(MemoryEvent(
                event_type="write",
                key="example_memory",
                value=payload,
            ))
            self.final_output = "Memory updated."
        else:
            self.final_output = f"Processed workflow request: {payload}"

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


def create_workflow(config):
    return ExampleWorkflow(config)
