"""Command line entry point. Network discovery requires an explicit URL."""
import argparse
import json
import sys
from pathlib import Path
from .analyst import LangChainAnalyst
from .engine import Inspector
from .models import MAX_BYTES, HumanDecision, ScanOptions
from .discovery import DiscoveryError, discover


def read_input(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Input exceeds 1 MB")
    return data.decode('utf-8')


def make_inspector(model=None):
    if not model:
        return Inspector()
    from langchain.chat_models import init_chat_model
    # Explicit model selection; no automatic provider installation or fallback.
    chat = init_chat_model(model, timeout=30, max_retries=0, max_tokens=4000)
    return Inspector(LangChainAnalyst(chat))


def main(argv=None):
    parser = argparse.ArgumentParser(description="MCP Sentinel — Inspect tools. Detect threats. Track changes.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Inspect a tools/list JSON file or public HTTPS MCP URL")
    scan.add_argument("input", help="Tool export path or public HTTPS MCP endpoint")
    scan.add_argument("--baseline", help="Previous tool export or Sentinel JSON report")
    scan.add_argument("--output", help="Write the full JSON report")
    scan.add_argument("--model", help="Opt in to AI: explicit LangChain provider:model identifier")
    scan.add_argument("--review", action="store_true", help="Pause for interactive human review")
    scan.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="Finding severity threshold for exit 1")
    serve = commands.add_parser("serve", help="Launch the local browser interface")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--model", help="Enable optional AI analysis with this provider:model")
    args = parser.parse_args(argv)
    try:
        inspector = make_inspector(args.model)
        if args.command == "serve":
            from .web import serve
            serve(inspector, port=args.port, ai_available=bool(args.model))
            return 0
        if args.review and not sys.stdin.isatty():
            raise ValueError("--review needs an interactive terminal")
        payload = discover(args.input) if '://' in args.input else read_input(args.input)
        report = inspector.inspect(payload,
            baseline=read_input(args.baseline) if args.baseline else None,
            options=ScanOptions(ai=bool(args.model), human_review=args.review))
        if report.status == "awaiting_review":
            decisions = []
            for finding in report.findings:
                print(f"{finding.id} [{finding.severity}] {finding.tool}: {finding.summary}", file=sys.stderr)
                print(json.dumps([e.model_dump() for e in finding.evidence]), file=sys.stderr)
                while True:
                    choice = input("Disposition (confirmed/dismissed/needs_investigation): ").strip()
                    if choice in {"confirmed", "dismissed", "needs_investigation"}:
                        break
                rationale = ""
                while not rationale.strip():
                    rationale = input("Rationale: ")
                decisions.append(HumanDecision(finding_id=finding.id, disposition=choice, rationale=rationale))
            report = inspector.resume(report.scan_id, decisions)
        rendered = report.model_dump_json(indent=2)
        if args.output:
            Path(args.output).write_text(rendered + '\n', encoding='utf-8')
        else:
            print(rendered)
        if report.status in {"failed", "degraded"}:
            return 2
        levels = ["low", "medium", "high", "critical"]
        if args.fail_on and any(levels.index(f.severity) >= levels.index(args.fail_on) for f in report.findings):
            return 1
        return 0
    except DiscoveryError as exc:
        print(f"mcp-sentinel: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, ImportError) as exc:
        print(f"mcp-sentinel: {type(exc).__name__}: check input, model configuration and dependencies", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
