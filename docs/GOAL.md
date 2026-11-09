# Project: MCP Sentinel

You are a senior Python engineer, AI agent architect, LangGraph specialist, and application security engineer.

Help me design and implement **MCP Sentinel**, an open-source, AI-powered security inspector for Model Context Protocol (MCP) servers.

**GitHub repository:** `mcp-sentinel`  
**Project name:** MCP Sentinel  
**Tagline:** Inspect tools. Detect threats. Track changes.

The goal is to build a genuinely useful, production-minded open-source project that demonstrates modern agentic AI engineering and has strong potential to attract interest on GitHub and LinkedIn.

## 1. Background and learning objectives

Completed the Coursera course:

**Agentic AI with LangChain and LangGraph**

https://www.coursera.org/learn/agentic-ai-with-langchain-and-langgraph

I want MCP Sentinel to be a practical application of the technologies and architectural concepts introduced in this course.

In particular:

- LangChain for LLM integration and structured outputs.
- **LangGraph as the primary orchestration framework.**
- Stateful agent workflows.
- Conditional routing and graph-based execution.
- ReAct-style reasoning and tool use.
- Reflection and self-critique for improving analysis quality.
- Multi-agent collaboration when justified.
- Human-in-the-loop review for uncertain or high-risk findings.
- Agentic retrieval when useful for consulting trusted security guidance.

**LangGraph must be used in the actual implementation, not merely listed as a dependency or presented in documentation.**

Build a functional `StateGraph` that orchestrates the security inspection process and is used by both the CLI and web interface.

The project should demonstrate that I understand how to engineer agentic systems, not simply call an LLM.

However, avoid unnecessary complexity. Every agent, graph node, and tool should have a clearly defined responsibility.

## 2. Product vision

MCP Sentinel analyzes MCP server tool definitions, detects potential security risks, explains its findings, and tracks changes to previously inspected tools.

It should answer:

1. What tools and capabilities does this MCP server expose?
2. Do tool definitions contain suspicious instructions or prompt injection attempts?
3. Could tools access sensitive data or perform dangerous operations?
4. Are there potential data exfiltration risks?
5. Have tool descriptions or schemas changed since a previous inspection?
6. Which findings need human review?
7. What concrete mitigations should developers consider?

MCP Sentinel must distinguish observed evidence, possible capabilities, heuristic findings, and unverified runtime behavior.

It is a security assessment tool, not a guarantee of safety.

## 3. Mandatory LangGraph architecture

Implement the inspection engine using LangGraph's `StateGraph`.

Design a typed shared state, preferably using `TypedDict` and Pydantic models.

The main graph should resemble:

```text
START
  |
  v
Load Tool Definitions
  |
  v
Validate & Normalize
  |
  v
Deterministic Security Scan
  |
  v
Assess Findings
  |
  +---- No suspicious findings ----+
  |                                |
  v                                |
AI Security Analyst                |
  |                                |
  v                                |
Reflection / Critic                |
  |                                |
  v                                |
Consolidate Findings <-------------+
  |
  v
Compare Baseline
  |
  v
Generate Report
  |
  v
END
```

This is a starting architecture; improve it where justified.

### Required graph features

Implement:

- Real graph nodes with separate responsibilities.
- Explicit edges and conditional routing.
- Typed graph state.
- Structured inputs and outputs.
- Error handling and bounded execution.
- Conditional execution of expensive analysis.
- An inspection trace showing which nodes ran.
- A no-LLM operating mode.
- Unit tests for graph transitions.
- Integration tests covering complete graph execution.

The graph must execute for every scan, including deterministic-only scans.

The LLM-powered security analyst should be skipped when AI analysis is disabled.

## 4. Agentic security analysis

Implement an AI-assisted analysis layer inside LangGraph.

### Security Analyst

Responsibilities:

- Examine suspicious tool definitions.
- Evaluate whether suspicious text appears to be an instruction directed at an AI agent.
- Differentiate legitimate documentation from malicious behavioral instructions.
- Analyze potential security implications.
- Explain findings with concrete evidence.

Use structured Pydantic outputs.

### Reflection / Critic

Implement a separate review stage that:

- Challenges unsupported conclusions.
- Identifies possible false positives.
- Checks whether evidence actually supports a finding.
- Distinguishes dangerous capabilities from malicious behavior.
- Identifies uncertainty.
- Suggests corrections to the initial assessment.

The critic must not overwrite deterministic evidence or silently remove findings.

Use a bounded review process, with no unbounded agent loops.

### ReAct-style investigation

Demonstrate tool-assisted reasoning where it adds real value.

Provide the analyst with a small set of safe, read-only analysis tools, such as:

- Retrieve a normalized tool definition.
- Inspect schema fields.
- Retrieve relevant deterministic findings
