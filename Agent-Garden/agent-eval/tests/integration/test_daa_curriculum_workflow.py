import sys
from pathlib import Path

import yaml

sys.path.insert(0, ".")

from adapter.workflow_adapter import create_workflow_adapter
from daa_curriculum.workflow import DaaCurriculumWorkflow


FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def load_config() -> dict:
    path = FIXTURES / "daa_curriculum_workflow.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["_target_path"] = str(path)
    return data


def load_runtime_config() -> dict:
    config = load_config()["config"]
    config["fixture_html_path"] = str(FIXTURES / config["fixture_html_path"])
    return config


def test_daa_curriculum_workflow_answers_with_citations_and_review():
    workflow = DaaCurriculumWorkflow(load_runtime_config())
    workflow.setup()

    result = workflow.run_scenario(
        "Khóa 2025 có ngành Khoa học dữ liệu không?",
        "user_prompt",
    )
    trace = workflow.get_trace()

    assert "Trích dẫn:" in result["result"]
    assert "[C" in result["result"]
    assert "Đánh giá nội bộ:" in result["result"]
    assert trace.tool_calls
    assert trace.inter_agent_messages
    assert trace.memory_events
    assert trace.metadata["review"]["overall_score"] > 0


def test_daa_curriculum_workflow_can_be_task2_input_via_workflow_adapter():
    adapter = create_workflow_adapter(load_config())
    adapter.setup()
    adapter.run_scenario("Cho tôi biết thông tin CTĐT khóa 2024", "user_prompt")
    trace = adapter.get_trace()

    assert trace.target_id == "daa_curriculum_fixture"
    assert trace.final_output
    assert trace.tool_calls[0].name == "search_curriculum"
    assert trace.memory_events[0].key == "curriculum_documents"
    assert trace.inter_agent_messages
    assert trace.metadata["target_input_type"] == "workflow"


def test_daa_curriculum_workflow_reset_isolates_questions():
    adapter = create_workflow_adapter(load_config())
    adapter.setup()
    adapter.run_scenario("Hỏi về khóa 2025", "user_prompt")
    first_trace = adapter.get_trace()

    adapter.reset()
    adapter.run_scenario("Hỏi về khóa 2024", "user_prompt")
    second_trace = adapter.get_trace()

    assert "2025" in first_trace.messages[0].content
    user_messages = [message.content for message in second_trace.messages if message.role == "user"]
    assert user_messages == ["Hỏi về khóa 2024"]
