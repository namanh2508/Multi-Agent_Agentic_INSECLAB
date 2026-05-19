"""Tests for adapter module."""
import sys
sys.path.insert(0, ".")
from adapter.mock_adapter import MockAdapter
from core.models import ToolCall, MemoryEvent, Message


def test_setup_and_reset():
    adapter = MockAdapter({"target_id": "test"})
    adapter.setup()
    adapter.reset()
    assert len(adapter.get_messages()) == 0


def test_run_scenario():
    adapter = MockAdapter()
    adapter.setup()
    result = adapter.run_scenario("test payload", "user_prompt")
    assert "result" in result
    assert result["surface"] == "user_prompt"


def test_get_trace():
    adapter = MockAdapter({"target_id": "my_agent"})
    adapter.setup()
    adapter.run_scenario("Hello", "user_prompt")
    trace = adapter.get_trace()
    assert trace.target_id == "my_agent"
    assert len(trace.messages) > 0


def test_set_tool_calls():
    adapter = MockAdapter()
    adapter.setup()
    tool_calls = [ToolCall(id="1", name="test_tool", arguments={})]
    adapter.set_tool_calls(tool_calls)
    assert len(adapter.get_tool_calls()) == 1


def test_set_memory_events():
    adapter = MockAdapter()
    adapter.setup()
    events = [MemoryEvent(event_type="write", key="test", value="data")]
    adapter.set_memory_events(events)
    assert len(adapter.get_memory_events()) == 1
