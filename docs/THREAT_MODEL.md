# Threat model

MCP Sentinel reads attacker-controlled metadata. A malicious export can attack the parser, regex rules, LLM, browser renderer or human reviewer. The inspector also handles sensitive legitimate tool metadata. The desired outcome is an evidence-backed review artifact, never automatic permission to run a target tool.

| Boundary | Controls | Residual risk |
| --- | --- | --- |
| Export → parser | File/request limits, tool count, unique names, typed basic metadata, reject incomplete pagination | Full JSON Schema semantics and server identity are not verified; deeply nested documents may be rejected |
| MCP URL → discovery | Public HTTPS only, validate all DNS answers and connect to a numeric IP with original TLS identity, no proxies/redirects/compression, total and HTTP timeouts, streamed byte budget, pagination and inventory limits | Server sees the connection; TLS does not establish server trustworthiness; metadata may change while pages are fetched; network/DNS infrastructure remains trusted |
| Metadata → deterministic rules | Static rules, literal quotes and paths, no code evaluation | False positives, omissions, obfuscation, Unicode tricks and negated examples |
| Metadata → model | Explicit opt-in, policy separate from untrusted data, only local readers, bounded turns/calls/context/output | Prompt injection can still influence conclusions; model provider and configured tracing can see metadata |
| Model → report | Pydantic outputs, quote/path validation, known critic IDs, additive critique, original findings retained | Literal evidence may be interpreted incorrectly; summaries and mitigations remain untrusted suggestions |
| Report → browser | DOM textContent, no metadata HTML, CSP, no third-party scripts | Untrusted text can socially engineer a human; do not blindly copy suggested commands |
| Browser → local service | Loopback binding, exact Host, random request token, JSON only, no CORS allowance | No user authentication, protection from other local processes, concurrency isolation or hostile local OS |
| Review → decision | Real checkpoint pause, exact finding-ID coverage, validated dispositions, rationale required | No reviewer identity/authorization; in-memory sessions lost on exit or eviction |
| Snapshot → change report | Deterministic canonical hashing, full preserved metadata comparison | No signing or server identity binding; attacker-controlled baselines conceal changes |

The critic receives the original selected metadata as well as assessments, rather than trusting analyst conclusions alone. It is still another model call and not an independent security authority. A critic failure cannot erase evidence or make a scan clean. Every finding remains review-required, including after human dismissal; recorded dispositions express the reviewer decision without rewriting the observed evidence.

Sentinel never starts MCP servers, invokes target tools, executes code from schemas, resolves external schema references, or retrieves arbitrary websites. Explicit URL input enables MCP initialization, tools/list pagination, optional server notifications, and session cleanup through Streamable HTTP. Sampling and elicitation are rejected, and no local roots are exposed. Incomplete discovery fails without scanning a partial inventory. Baselines remain local exports or reports. Authentication, private-network targets and legacy HTTP+SSE discovery are unsupported. Explicitly enabled AI calls also use the network. User-enabled provider tracing may send data externally. Reports contain evidence that may itself include sensitive text: redact exports before scanning and protect report storage.

Bounded execution means finite graph transitions, bounded AI turns and calls, size budgets and provider request timeouts. URL discovery additionally uses a 30-second total timeout, 10-second HTTP timeouts, a 2 MB combined response-body budget, a 200-page limit and the existing 1 MB/200-tool inventory limits. The synchronous local server processes one request at a time, so discovery or AI analysis may temporarily block other requests. It is not suitable for public deployment or hostile multi-tenant workloads. Embedded chat implementations must implement their own timeout behavior. Additional process resource limits would be needed for a hardened service.

Please report reproducible issues with synthetic, redacted fixtures. Do not include credentials or proprietary server exports in public issues. No private reporting address has been configured yet; establish one before publishing a production support claim.
