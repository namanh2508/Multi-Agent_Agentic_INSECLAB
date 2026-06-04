from pydantic import BaseModel, Field
from typing import Any, Optional
from datetime import datetime, timezone

from .enums import ASICategory, Severity, AttackSurface, AttackState


class AttackCase(BaseModel):
    id: str
    category: ASICategory
    objective: str
    surface: AttackSurface
    payload: str
    surface_policy: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    state: AttackState = AttackState.PENDING


class ToolCall(BaseModel):
    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: Any = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Message(BaseModel):
    role: str
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MemoryEvent(BaseModel):
    event_type: str
    key: str
    value: Any = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class InterAgentMessage(BaseModel):
    from_agent: str
    to_agent: str
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AgentTrace(BaseModel):
    target_id: str
    messages: list[Message] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    memory_events: list[MemoryEvent] = Field(default_factory=list)
    inter_agent_messages: list[InterAgentMessage] = Field(default_factory=list)
    final_output: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvidenceItem(BaseModel):
    source: str
    content: str
    snippet: str


class Finding(BaseModel):
    attack_case_id: str
    category: ASICategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    explanation: str
    trace_snippet: list[dict[str, Any]] = Field(default_factory=list)
    is_vulnerable: bool = True


class CategorySummary(BaseModel):
    category: ASICategory
    total_cases: int = 0
    vulnerable_count: int = 0
    by_severity: dict[Severity, int] = Field(default_factory=dict)


class EvalReport(BaseModel):
    target_id: str
    total_cases: int
    findings: list[Finding] = Field(default_factory=list)
    category_summary: dict[ASICategory, CategorySummary] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)

    def get_summary(self) -> dict[str, Any]:
        success_rate = self.metadata.get("success_rate", 0.0)
        return {
            "total_cases": self.total_cases,
            "total_findings": len(self.findings),
            "success_rate": success_rate,
            "categories": {
                cat.value: sum(1 for f in self.findings if f.category == cat)
                for cat in ASICategory
            },
            "severities": {
                sev.value: sum(1 for f in self.findings if f.severity == sev)
                for sev in Severity
            },
        }


class AdapterConfig(BaseModel):
    adapter_type: str
    config: dict[str, Any] = Field(default_factory=dict)


class EvalConfig(BaseModel):
    target_id: str
    adapter_config: AdapterConfig
    categories: list[ASICategory] = Field(default_factory=list)
    n_variants: int = 5
    max_attacks: int = 50
    judge_model: str = "gpt-4o"
    mutator_model: str = "gpt-4o-mini"
