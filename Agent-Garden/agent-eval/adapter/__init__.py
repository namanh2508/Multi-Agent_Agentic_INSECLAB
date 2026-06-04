from .base import BaseAdapter
from .mock_adapter import MockAdapter
from .ollama_adapter import OllamaAdapter
from .custom_adapter import CustomAdapter, get_adapter
from .workflow_adapter import WorkflowAdapter, create_workflow_adapter

try:
    from .multiagent import MultiAgentAdapter
    _multiagent_available = True
except ImportError:
    _multiagent_available = False

__all__ = [
    "BaseAdapter",
    "MockAdapter",
    "OllamaAdapter",
    "CustomAdapter",
    "WorkflowAdapter",
    "create_workflow_adapter",
    "get_adapter",
]
if _multiagent_available:
    __all__.append("MultiAgentAdapter")
