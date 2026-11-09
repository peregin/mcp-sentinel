"""Validated public contracts. Tool metadata and model responses are untrusted."""
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_BYTES = 1_000_000
MAX_TOOLS = 200
Severity = Literal["low", "medium", "high", "critical"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolDefinition(BaseModel):
    # Preserve future MCP metadata, annotations, output schemas and extensions for scanning/diffing.
    model_config = ConfigDict(extra="allow")
    name: str = Field(min_length=1, max_length=128, strict=True)
    description: str = Field(default="", max_length=50_000, strict=True)
    inputSchema: dict[str, Any]

    @field_validator("inputSchema")
    @classmethod
    def object_schema(cls, value):
        if value.get("type") != "object":
            raise ValueError("inputSchema must declare type: object")
        return value


class Evidence(StrictModel):
    path: str
    quote: str = Field(min_length=1, max_length=2000)


class Finding(StrictModel):
    id: str
    tool: str
    rule: str
    severity: Severity
    kind: Literal["heuristic", "possible_capability", "ai_assessment"]
    summary: str
    evidence: list[Evidence] = Field(min_length=1)
    mitigation: str
    confidence: Literal["low", "medium", "high"] = "medium"
    review_required: bool = True


class Assessment(StrictModel):
    tool: str
    severity: Severity
    summary: str = Field(min_length=1, max_length=2000)
    evidence: list[Evidence] = Field(min_length=1, max_length=10)
    mitigation: str = Field(min_length=1, max_length=2000)
    confidence: Literal["low", "medium", "high"]


class Analysis(StrictModel):
    assessments: list[Assessment] = Field(default_factory=list, max_length=100)


class Critique(StrictModel):
    target_id: str
    verdict: Literal["supported", "uncertain", "possible_false_positive"]
    explanation: str = Field(min_length=1, max_length=2000)
    suggested_correction: str = Field(max_length=2000)


class CriticOutput(StrictModel):
    reviews: list[Critique] = Field(default_factory=list, max_length=200)


class HumanDecision(StrictModel):
    finding_id: str
    disposition: Literal["confirmed", "dismissed", "needs_investigation"]
    rationale: str = Field(min_length=1, max_length=2000)


class Change(StrictModel):
    tool: str
    status: Literal["added", "removed", "modified"]
    fields: list[str] = Field(default_factory=list)


class ScanOptions(StrictModel):
    ai: bool = False
    human_review: bool = False
    max_rounds: int = Field(default=2, ge=1, le=3)
    max_tool_calls: int = Field(default=6, ge=1, le=10)
    max_ai_tools: int = Field(default=20, ge=1, le=30)


class Report(StrictModel):
    format_version: Literal[1] = 1
    scan_id: str
    generated_at: str
    status: Literal["complete", "awaiting_review", "failed", "degraded"]
    tools: list[ToolDefinition] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    critiques: list[Critique] = Field(default_factory=list)
    decisions: list[HumanDecision] = Field(default_factory=list)
    changes: list[Change] = Field(default_factory=list)
    baseline_compared: bool = False
    snapshot_hash: str = ""
    trace: list[str] = Field(default_factory=list)
    investigation: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    limitations: str = (
        "Static metadata assessment only. Findings are heuristics or possible capabilities; "
        "runtime behavior, exploitability and server safety are unverified. "
        "No findings does not establish safety. Tool annotations are untrusted claims."
    )
