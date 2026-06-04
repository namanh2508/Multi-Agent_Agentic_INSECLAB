from .judge import VulnerabilityJudge
from .rule_based_judge import RuleBasedJudge, Judge
from .ollama_judge import OllamaJudge
from .policy_loader import PolicyLoader
from .evidence import EvidenceExtractor
from .scorer import SeverityScorer

__all__ = [
    "VulnerabilityJudge",
    "RuleBasedJudge",
    "OllamaJudge",
    "Judge",
    "PolicyLoader",
    "EvidenceExtractor",
    "SeverityScorer",
    "get_judge",
]


def get_judge(provider: str, **kwargs):
    """Factory to create a judge by provider name.

    Args:
        provider: One of 'rule', 'ollama', 'openai'
        **kwargs: Passed to the judge constructor

    Returns:
        A Judge instance

    Raises:
        ValueError: If provider is not recognized
    """
    if provider == "rule":
        return RuleBasedJudge()
    elif provider == "ollama":
        return OllamaJudge(**kwargs)
    elif provider == "openai":
        return VulnerabilityJudge(**kwargs)
    else:
        raise ValueError(
            f"Unknown judge provider: '{provider}'. "
            "Available: rule, ollama, openai"
        )
