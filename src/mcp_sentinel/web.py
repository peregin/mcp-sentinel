"""Loopback-only development UI. No remote targets, filesystem paths or uploads to services."""
import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.resources import files
from .engine import Inspector
from .models import MAX_BYTES, HumanDecision, ScanOptions


def create_server(inspector: Inspector, port=8765, ai_available=False):
    token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def send(self, status, body, content_type="application/json"):
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(data)

        def valid_host(self):
            return self.headers.get('Host') == f"127.0.0.1:{self.server.server_port}"

        def do_GET(self):
            if not self.valid_host():
                self.send(403, '{}')
                return
            assets = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'), '/style.css': ('style.css', 'text/css')}
            if self.path not in assets:
                self.send(404, '{}')
                return
            name, mime = assets[self.path]
            body = files('mcp_sentinel').joinpath(name).read_text(encoding='utf-8')
            if self.path == '/':
                body = body.replace('__TOKEN__', token).replace('__AI__', 'true' if ai_available else 'false')
            self.send(200, body, mime)

        def do_POST(self):
            if not self.valid_host() or not secrets.compare_digest(self.headers.get('X-Sentinel-Token', ''), token):
                self.send(403, '{}')
                return
            try:
                if self.headers.get('Content-Type') != 'application/json':
                    raise ValueError('Expected JSON')
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= MAX_BYTES * 2 + 10000:
                    self.send(413, '{"error":"Request exceeds size limit"}')
                    return
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError('Incomplete body')
                body = json.loads(raw)
                if not isinstance(body, dict):
                    raise ValueError('Expected object')
                if self.path == '/api/scan':
                    if body.get('ai') and not ai_available:
                        raise ValueError('AI is not configured')
                    report = inspector.inspect(body['payload'], baseline=body.get('baseline'),
                        options=ScanOptions(ai=body.get('ai', False), human_review=body.get('review', False)))
                elif self.path == '/api/review':
                    report = inspector.resume(body['scan_id'], [HumanDecision.model_validate(d) for d in body['decisions']])
                else:
                    self.send(404, '{}')
                    return
                self.send(200, report.model_dump_json())
            except (ValueError, KeyError, TypeError, RecursionError):
                self.send(400, '{"error":"Invalid request or review decisions"}')

        def log_message(self, *_):
            pass  # Never log metadata, tokens or request bodies.

    return HTTPServer(('127.0.0.1', port), Handler)


def serve(inspector, port=8765, ai_available=False):
    with create_server(inspector, port, ai_available) as server:
        print(f"MCP Sentinel: http://127.0.0.1:{server.server_port} (Ctrl+C to stop)", flush=True)
        server.serve_forever()
