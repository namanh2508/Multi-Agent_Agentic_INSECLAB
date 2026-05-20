import importlib
import inspect
import sys
from pathlib import Path
from typing import Any

from .base import BaseAdapter
from core.exceptions import AdapterError
from core.models import AgentTrace, Message, ToolCall, MemoryEvent, InterAgentMessage


REQUIRED_WORKFLOW_METHODS = ("setup", "reset", "run_scenario")


def create_workflow_adapter(config: dict[str, Any] | None = None) -> BaseAdapter:
    """Create an adapter from a workflow target config."""
    config = config or {}
    workflow = _load_workflow_from_config(config)

    if isinstance(workflow, BaseAdapter):
        return workflow

    return WorkflowAdapter(workflow=workflow, config=config)


class WorkflowAdapter(BaseAdapter):
    """Adapter that wraps a local workflow agent object.

    The wrapped workflow must implement setup(), reset(), and
    run_scenario(payload, surface). It may return AgentTrace directly through
    get_trace(); otherwise this adapter builds AgentTrace from trace accessors.
    """

    def __init__(
        self,
        workflow: Any | None = None,
        config: dict[str, Any] | None = None,
    ):
        super().__init__(config)
        self.workflow = workflow if workflow is not None else _load_workflow_from_config(self.config)
        self._last_result: Any = None
        self._validate_workflow()

    def setup(self) -> None:
        self.workflow.setup()
        self._initialized = True

    def reset(self) -> None:
        self.workflow.reset()
        self._last_result = None

    def run_scenario(self, payload: str, surface: str) -> dict[str, Any]:
        if not self._initialized:
            raise AdapterError("Workflow adapter not initialized. Call setup() first.")

        self._last_result = self.workflow.run_scenario(payload, surface)
        if isinstance(self._last_result, dict):
            return self._last_result
        return {"result": self._last_result, "surface": surface}

    def get_final_output(self) -> str:
        if hasattr(self.workflow, "get_final_output"):
            return str(self.workflow.get_final_output())
        if isinstance(self._last_result, dict):
            return str(self._last_result.get("result", ""))
        return "" if self._last_result is None else str(self._last_result)

    def get_tool_calls(self) -> list[ToolCall]:
        return _coerce_tool_calls(_call_optional(self.workflow, "get_tool_calls", []))

    def get_messages(self) -> list[Message]:
        return _coerce_messages(_call_optional(self.workflow, "get_messages", []))

    def get_memory_events(self) -> list[MemoryEvent]:
        return _coerce_memory_events(_call_optional(self.workflow, "get_memory_events", []))

    def get_inter_agent_messages(self) -> list[InterAgentMessage]:
        return _coerce_inter_agent_messages(
            _call_optional(self.workflow, "get_inter_agent_messages", [])
        )

    def get_trace(self) -> AgentTrace:
        if hasattr(self.workflow, "get_trace"):
            trace = self.workflow.get_trace()
            if isinstance(trace, AgentTrace):
                return _with_workflow_metadata(trace, self.config)
            if isinstance(trace, dict):
                return _with_workflow_metadata(AgentTrace(**trace), self.config)
            raise AdapterError(
                "Workflow get_trace() must return AgentTrace or a compatible dict."
            )

        return AgentTrace(
            target_id=self.config.get("target_id", "workflow"),
            messages=self.get_messages(),
            tool_calls=self.get_tool_calls(),
            memory_events=self.get_memory_events(),
            inter_agent_messages=self.get_inter_agent_messages(),
            final_output=self.get_final_output(),
            metadata=_workflow_metadata(self.config),
        )

    def _validate_workflow(self) -> None:
        missing = [m for m in REQUIRED_WORKFLOW_METHODS if not callable(getattr(self.workflow, m, None))]
        if missing:
            raise AdapterError(
                "Workflow target is missing required method(s): "
                + ", ".join(missing)
            )

        if hasattr(self.workflow, "get_trace"):
            return

        if not callable(getattr(self.workflow, "get_final_output", None)):
            raise AdapterError(
                "Workflow target must implement get_trace() or get_final_output()."
            )

        capabilities = self.config.get("capabilities", {}) or {}
        capability_methods = {
            "tools": "get_tool_calls",
            "memory": "get_memory_events",
            "inter_agent_messages": "get_inter_agent_messages",
        }
        missing_trace = [
            method
            for capability, method in capability_methods.items()
            if capabilities.get(capability) and not callable(getattr(self.workflow, method, None))
        ]
        if missing_trace:
            raise AdapterError(
                "Workflow capabilities require missing trace method(s): "
                + ", ".join(missing_trace)
            )


def _load_workflow_from_config(config: dict[str, Any]) -> Any:
    entrypoint = config.get("entrypoint")
    if not entrypoint:
        raise AdapterError("Workflow target config must define 'entrypoint'.")

    _extend_pythonpath(config)

    module_name, attr_name = _parse_entrypoint(entrypoint)
    try:
        module = importlib.import_module(module_name)
    except Exception as e:
        raise AdapterError(f"Failed to import workflow module '{module_name}': {e}")

    try:
        entry = getattr(module, attr_name)
    except AttributeError:
        raise AdapterError(f"Workflow entrypoint not found: {entrypoint}")

    entrypoint_type = config.get("entrypoint_type", "factory")
    runtime_config = dict(config.get("config", {}) or {})
    for key in ("target_id", "model", "base_url", "capabilities"):
        if key in config:
            runtime_config.setdefault(key, config[key])
    _resolve_runtime_paths(runtime_config, config)

    if entrypoint_type == "factory":
        workflow = _call_entrypoint(entry, runtime_config)
    elif entrypoint_type == "class":
        workflow = _call_entrypoint(entry, runtime_config)
    else:
        raise AdapterError(
            "Unsupported workflow entrypoint_type: "
            f"{entrypoint_type}. Use 'factory' or 'class'."
        )

    if workflow is None:
        raise AdapterError(f"Workflow entrypoint returned None: {entrypoint}")

    return workflow


def _parse_entrypoint(entrypoint: str) -> tuple[str, str]:
    if ":" not in entrypoint:
        raise AdapterError(
            "Workflow entrypoint must use 'module:function' format."
        )
    module_name, attr_name = entrypoint.split(":", 1)
    if not module_name or not attr_name:
        raise AdapterError(
            "Workflow entrypoint must include both module and function/class name."
        )
    return module_name, attr_name


def _extend_pythonpath(config: dict[str, Any]) -> None:
    paths = []
    target_path = config.get("_target_path")
    if target_path:
        paths.append(str(Path(target_path).resolve().parent))
    paths.extend(str(Path(p).resolve()) for p in config.get("pythonpath", []) or [])

    for path in paths:
        if path and path not in sys.path:
            sys.path.insert(0, path)


def _resolve_runtime_paths(runtime_config: dict[str, Any], config: dict[str, Any]) -> None:
    target_path = config.get("_target_path")
    if not target_path:
        return

    base_dir = Path(target_path).resolve().parent
    for key in ("fixture_html_path",):
        value = runtime_config.get(key)
        if value and not Path(value).is_absolute():
            runtime_config[key] = str((base_dir / value).resolve())


def _call_entrypoint(entry: Any, runtime_config: dict[str, Any]) -> Any:
    try:
        signature = inspect.signature(entry)
    except (TypeError, ValueError):
        return entry(runtime_config)

    accepted_params = [
        p
        for p in signature.parameters.values()
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
    ]

    if not accepted_params:
        return entry()
    return entry(runtime_config)


def _call_optional(workflow: Any, method_name: str, default: Any) -> Any:
    method = getattr(workflow, method_name, None)
    if callable(method):
        return method()
    return default


def _coerce_messages(items: Any) -> list[Message]:
    return [_coerce_model(item, Message) for item in (items or [])]


def _coerce_tool_calls(items: Any) -> list[ToolCall]:
    return [_coerce_model(item, ToolCall) for item in (items or [])]


def _coerce_memory_events(items: Any) -> list[MemoryEvent]:
    return [_coerce_model(item, MemoryEvent) for item in (items or [])]


def _coerce_inter_agent_messages(items: Any) -> list[InterAgentMessage]:
    return [_coerce_model(item, InterAgentMessage) for item in (items or [])]


def _coerce_model(item: Any, model: type) -> Any:
    if isinstance(item, model):
        return item
    if isinstance(item, dict):
        return model(**item)
    raise AdapterError(
        f"Workflow trace item must be {model.__name__} or dict, got {type(item).__name__}."
    )


def _workflow_metadata(config: dict[str, Any]) -> dict[str, Any]:
    metadata = {
        **config.copy(),
        "target_input_type": "workflow",
    }
    metadata.pop("_target_path", None)
    return metadata


def _with_workflow_metadata(trace: AgentTrace, config: dict[str, Any]) -> AgentTrace:
    metadata = {
        **trace.metadata,
        **_workflow_metadata(config),
    }
    return trace.model_copy(update={"metadata": metadata})
