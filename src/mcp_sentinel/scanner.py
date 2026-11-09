"""Small, explainable rules with exact JSON Pointer evidence; no server execution."""
import hashlib
import json
import re
from typing import Any
from .models import Evidence, Finding, ToolDefinition


def strings(value: Any, path: str = ""):
    """Yield keys and string values; include schema descriptions, enums and extensions."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            pointer = path + "/" + key.replace("~", "~0").replace("/", "~1")
            yield pointer + "/@key", key
            yield from strings(item, pointer)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from strings(item, f"{path}/{i}")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


# These flag text, not intent. Legitimate warnings and examples may also match.
RULES = [
    ("instruction_override", "high", "heuristic",
     r"\b(?:ignore|disregard|override)\b.{0,60}\b(?:previous|system|developer|instructions?|polic(?:y|ies))\b",
     "Possible instruction hierarchy override",
     "Keep server metadata outside trusted instructions; review the quoted text and require approval."),
    ("concealment", "high", "heuristic",
     r"\b(?:do not|don't|never)\s+(?:tell|inform|reveal|disclose)\b|\bhide\b.{0,30}\b(?:user|activity|action)\b",
     "Possible instruction to conceal behavior",
     "Remove agent-directed secrecy instructions and make tool actions visible to users."),
    ("sensitive_data", "medium", "possible_capability",
     r"\b(?:passwords?|credentials?|secrets?|api[_ -]?keys?|private[_ -]?keys?|access[_ -]?tokens?)\b|\.ssh\b|\.env\b",
     "Metadata references sensitive data",
     "Scope access, redact secrets and verify runtime authorization and logging."),
    ("dangerous_operation", "high", "possible_capability",
     r"\b(?:shell|exec(?:ute)?|subprocess|sudo|drop\s+table|delete|unlink|rm\s+-rf)\b",
     "Metadata suggests execution or destructive capabilities",
     "Use least privilege, constrained arguments, sandboxing and explicit approval for destructive actions."),
    ("outbound_destination", "medium", "possible_capability",
     r"https?://[^\s\"<>]+|\b(?:upload|exfiltrat\w*|send)\b.{0,60}\b(?:data|files?|secrets?|credentials?|tokens?)\b",
     "Possible outbound data destination or transfer capability",
     "Review destination ownership and payloads; enforce egress allowlists and redact sensitive data."),
]


def scan(tools: list[ToolDefinition]) -> list[Finding]:
    results = []
    for tool in tools:
        fields = list(strings(tool.model_dump()))
        for rule, severity, kind, pattern, summary, mitigation in RULES:
            evidence = []
            for path, text in fields:
                match = re.search(pattern, text, re.I | re.S)
                if match:
                    # Keep context while retaining a verifiable literal substring.
                    quote = text[max(0, match.start()-80):match.end()+80][:2000]
                    evidence.append(Evidence(path=path, quote=quote))
                    if len(evidence) == 10:
                        break
            if evidence:
                results.append(Finding(
                    id="det-" + fingerprint([tool.name, rule])[:16], tool=tool.name,
                    rule=rule, severity=severity, kind=kind, summary=summary,
                    evidence=evidence, mitigation=mitigation,
                ))
    return results
