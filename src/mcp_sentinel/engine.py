"""The shared, typed LangGraph pipeline used by every interface."""
import json
from collections import deque
from datetime import datetime, timezone
from typing import Any, TypedDict
from uuid import uuid4
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from .analyst import Analyst
from .models import (MAX_BYTES, MAX_TOOLS, Analysis, Change, CriticOutput, Finding,
                     HumanDecision, Report, ScanOptions, ToolDefinition)
from .scanner import canonical, fingerprint, scan, strings


class InspectionState(TypedDict, total=False):
    payload: Any
    baseline_payload: Any
    options: ScanOptions
    scan_id: str
    raw_tools: list[dict]
    tools: list[ToolDefinition]
    baseline: list[ToolDefinition] | None
    findings: list[Finding]
    ai_findings: list[Finding]
    selected: list[ToolDefinition]
    critiques: list
    decisions: list[HumanDecision]
    changes: list[Change]
    trace: list[str]
    investigation: list[str]
    errors: list[str]
    fatal: bool
    report: Report


def reject_nonfinite(value: str):
    raise ValueError(f"Non-finite JSON number: {value}")


def parse_payload(payload: Any) -> list:
    # Re-encode dictionaries too: programmatic callers have the same size limit.
    if isinstance(payload, str):
        if len(payload.encode()) > MAX_BYTES:
            raise ValueError("Input exceeds 1 MB")
        payload = json.loads(payload, parse_constant=reject_nonfinite)
    if len(canonical(payload).encode()) > MAX_BYTES:
        raise ValueError("Input exceeds 1 MB")
    if isinstance(payload, list):
        tools = payload
    elif isinstance(payload, dict):
        envelope = payload.get("result", payload)
        if not isinstance(envelope, dict):
            raise ValueError("Expected a tools/list result object")
        if envelope.get("nextCursor"):
            raise ValueError("Incomplete tools/list page: combine all pages before scanning")
        tools = envelope.get("tools")
    else:
        tools = None
    if not isinstance(tools, list) or len(tools) > MAX_TOOLS:
        raise ValueError(f"Expected tools array with at most {MAX_TOOLS} entries")
    return tools


def normalize(raw: list) -> list[ToolDefinition]:
    tools = [ToolDefinition.model_validate(item) for item in raw]
    if len({t.name for t in tools}) != len(tools):
        raise ValueError("Duplicate tool names")
    return sorted(tools, key=lambda t: t.name)


def route_validation(state: InspectionState) -> str:
    return "generate_report" if state.get("fatal") else "deterministic_scan"


def route_analysis(state: InspectionState) -> str:
    return "security_analyst" if state["options"].ai and state.get("selected") else "consolidate"


def update(state, node, **values):
    return {"trace": state.get("trace", []) + [node], **values}


class Inspector:
    """One inspector owns in-memory review sessions. Reuse it to resume a pause.

    AI errors produce degraded reports without losing deterministic findings.
    Invalid primary input produces a failed report, never a clean assessment.
    """
    def __init__(self, analyst: Analyst | None = None):
        self.analyst = analyst
        builder = StateGraph(InspectionState)
        for name in ("load", "validate", "deterministic_scan", "assess", "security_analyst",
                     "critic", "consolidate", "compare_baseline", "human_review", "generate_report"):
            builder.add_node(name, getattr(self, name))
        builder.add_edge(START, "load")
        builder.add_edge("load", "validate")
        builder.add_conditional_edges("validate", route_validation,
            {"generate_report": "generate_report", "deterministic_scan": "deterministic_scan"})
        builder.add_edge("deterministic_scan", "assess")
        builder.add_conditional_edges("assess", route_analysis,
            {"security_analyst": "security_analyst", "consolidate": "consolidate"})
        builder.add_edge("security_analyst", "critic")
        builder.add_edge("critic", "consolidate")
        builder.add_edge("consolidate", "compare_baseline")
        builder.add_edge("compare_baseline", "human_review")
        builder.add_edge("human_review", "generate_report")
        builder.add_edge("generate_report", END)
        # Permit only our validated checkpoint models; never enable pickle fallback.
        model_names = ("ScanOptions", "ToolDefinition", "Evidence", "Finding", "HumanDecision",
                       "Report", "Change", "Critique")
        self.memory = InMemorySaver(serde=JsonPlusSerializer(
            allowed_msgpack_modules=[("mcp_sentinel.models", name) for name in model_names]))
        self.pending = deque()
        self.graph = builder.compile(checkpointer=self.memory)

    def load(self, state):
        try:
            return update(state, "load", raw_tools=parse_payload(state["payload"]))
        except (ValueError, TypeError, RecursionError):
            return update(state, "load", fatal=True, errors=["Invalid input JSON, envelope or size limit"])

    def validate(self, state):
        if state.get("fatal"):
            return update(state, "validate")
        try:
            tools = normalize(state["raw_tools"])
        except (ValueError, TypeError, RecursionError):
            return update(state, "validate", fatal=True, errors=["Invalid tool definitions or duplicate names"])
        baseline = None
        errors = []
        if state.get("baseline_payload") is not None:
            try:
                baseline = normalize(parse_payload(state["baseline_payload"]))
            except (ValueError, TypeError, RecursionError):
                errors = ["Invalid baseline; comparison unavailable"]
        return update(state, "validate", tools=tools, baseline=baseline, errors=errors)

    def deterministic_scan(self, state):
        return update(state, "deterministic_scan", findings=scan(state["tools"]))

    def assess(self, state):
        names = {f.tool for f in state["findings"]}
        candidates = [t for t in state["tools"] if t.name in names]
        options = state["options"]
        errors = list(state["errors"])
        selected = candidates[:options.max_ai_tools]
        if options.ai and len(candidates) > len(selected):
            errors.append("AI tool budget exceeded; some suspicious tools received deterministic analysis only")
        # Explicitly bound model context. Avoid silently truncating evidence.
        if options.ai and len(canonical({"tools": [t.model_dump() for t in selected],
                "findings": [f.model_dump() for f in state["findings"] if f.tool in {t.name for t in selected}]})) > 60_000:
            selected = []
            errors.append("AI context budget exceeded; deterministic analysis retained")
        return update(state, "assess", selected=selected, errors=errors)

    def security_analyst(self, state):
        errors = list(state["errors"])
        accepted = []
        audit = []
        try:
            if self.analyst is None:
                raise RuntimeError("No analyst configured")
            selected = state["selected"]
            names = {t.name for t in selected}
            findings = [f for f in state["findings"] if f.tool in names]
            result, audit = self.analyst.analyze(selected, findings, state["options"])
            result = Analysis.model_validate(result)
            fields = {t.name: dict(strings(t.model_dump())) for t in selected}
            for item in result.assessments:
                if item.tool not in fields or any(
                    e.quote not in fields[item.tool].get(e.path, "") for e in item.evidence
                ):
                    errors.append("Rejected AI assessment with unsupported evidence")
                    continue
                accepted.append(Finding(
                    id="ai-" + fingerprint(item.model_dump())[:16],
                    rule="ai_assessment", kind="ai_assessment", **item.model_dump(),
                ))
        except Exception as exc:
            # Provider exception strings may contain secrets or input; only expose the class.
            errors.append(f"AI analysis unavailable ({type(exc).__name__}); deterministic evidence retained")
        return update(state, "security_analyst", ai_findings=accepted,
                      investigation=audit, errors=errors)

    def critic(self, state):
        errors = list(state["errors"])
        reviews = []
        try:
            if self.analyst is None:
                raise RuntimeError("No critic configured")
            names = {t.name for t in state["selected"]}
            findings = [f for f in state["findings"] + state.get("ai_findings", []) if f.tool in names]
            output = CriticOutput.model_validate(self.analyst.critique(state["selected"], findings))
            ids = {f.id for f in findings}
            seen = set()
            for review in output.reviews:
                if review.target_id not in ids or review.target_id in seen:
                    errors.append("Rejected critic review with unknown or duplicate finding ID")
                else:
                    reviews.append(review)
                    seen.add(review.target_id)
            if seen != ids:
                errors.append("Critic coverage incomplete; unreviewed findings require human review")
        except Exception as exc:
            errors.append(f"Critic unavailable ({type(exc).__name__}); findings retained")
        return update(state, "critic", critiques=reviews, errors=errors)

    def consolidate(self, state):
        combined = state["findings"] + state.get("ai_findings", [])
        return update(state, "consolidate", findings=list({f.id: f for f in combined}.values()))

    def compare_baseline(self, state):
        changes = []
        baseline = state.get("baseline")
        if baseline is not None:
            old = {t.name: t.model_dump() for t in baseline}
            new = {t.name: t.model_dump() for t in state["tools"]}
            for name in sorted(old.keys() | new.keys()):
                if name not in old:
                    changes.append(Change(tool=name, status="added"))
                elif name not in new:
                    changes.append(Change(tool=name, status="removed"))
                elif old[name] != new[name]:
                    fields = sorted(k for k in old[name].keys() | new[name].keys()
                                    if (k in old[name]) != (k in new[name]) or old[name].get(k) != new[name].get(k))
                    changes.append(Change(tool=name, status="modified", fields=fields))
        return update(state, "compare_baseline", changes=changes)

    def human_review(self, state):
        decisions = []
        if state["options"].human_review and state["findings"]:
            raw = interrupt({"finding_ids": [f.id for f in state["findings"]]})
            decisions = [HumanDecision.model_validate(d) for d in raw]
            if {d.finding_id for d in decisions} != {f.id for f in state["findings"]} or len(decisions) != len(state["findings"]):
                raise ValueError("Exactly one decision per finding is required")
        return update(state, "human_review", decisions=decisions)

    def make_report(self, state, pending=False):
        return Report(
            scan_id=state["scan_id"], generated_at=datetime.now(timezone.utc).isoformat(),
            status="failed" if state.get("fatal") else "awaiting_review" if pending else
                   "degraded" if state.get("errors") else "complete",
            tools=state.get("tools", []), findings=state.get("findings", []),
            critiques=state.get("critiques", []), decisions=state.get("decisions", []),
            changes=state.get("changes", []), baseline_compared=state.get("baseline") is not None,
            snapshot_hash=fingerprint([t.model_dump() for t in state.get("tools", [])]),
            trace=state.get("trace", []), investigation=state.get("investigation", []),
            errors=state.get("errors", []),
        )

    def generate_report(self, state):
        state = {**state, **update(state, "generate_report")}
        return {"trace": state["trace"], "report": self.make_report(state)}

    def inspect(self, payload, *, baseline=None, options=None) -> Report:
        scan_id = str(uuid4())
        config = {"configurable": {"thread_id": scan_id}, "recursion_limit": 20}
        state = self.graph.invoke({"payload": payload, "baseline_payload": baseline,
            "options": options or ScanOptions(), "scan_id": scan_id, "trace": [],
            "errors": [], "fatal": False}, config)
        if state.get("__interrupt__"):
            self.pending.append(scan_id)
            if len(self.pending) > 16:
                self.memory.delete_thread(self.pending.popleft())
            return self.make_report(state, pending=True)
        self.memory.delete_thread(scan_id)
        return state["report"]

    def resume(self, scan_id: str, decisions: list[HumanDecision]) -> Report:
        config = {"configurable": {"thread_id": scan_id}, "recursion_limit": 20}
        snapshot = self.graph.get_state(config)
        if not snapshot.next or "human_review" not in snapshot.next:
            raise ValueError("No pending review for this scan")
        parsed = [HumanDecision.model_validate(d) for d in decisions]
        ids = {f.id for f in snapshot.values["findings"]}
        if len(parsed) != len(ids) or {d.finding_id for d in parsed} != ids:
            raise ValueError("Exactly one decision per finding is required")
        result = self.graph.invoke(Command(resume=[d.model_dump() for d in parsed]), config)
        self.memory.delete_thread(scan_id)
        self.pending.remove(scan_id)
        return result["report"]
