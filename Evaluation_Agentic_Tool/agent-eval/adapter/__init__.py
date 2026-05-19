from .base import BaseAdapter
from .mock_adapter import MockAdapter
from .ollama_adapter import OllamaAdapter
from .custom_adapter import CustomAdapter, get_adapter

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
    "get_adapter",
]
if _multiagent_available:
    __all__.append("MultiAgentAdapter")
