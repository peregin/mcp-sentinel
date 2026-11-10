import asyncio
import contextlib
import copy
import io
import json
import socket
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from mcp_sentinel import discovery
from mcp_sentinel.cli import main
from mcp_sentinel.engine import Inspector
from test_engine import SUSPICIOUS

URL = 'https://weather.example/mcp'
PUBLIC_IP = '93.184.216.34'


class Chunks(httpx.AsyncByteStream):
    def __init__(self, data):
        self.data = data
        self.closed = False

    async def __aiter__(self):
        for offset in range(0, len(self.data), 128):
            yield self.data[offset:offset + 128]

    async def aclose(self):
        self.closed = True


class MCPFixture:
    """In-process MCP endpoint exercising the real SDK and guarded HTTP transport."""
    def __init__(self, pages, *, sse=False, status=None, capabilities=None, server_requests=False):
        self.pages = pages
        self.sse = sse
        self.status = status
        self.capabilities = {'tools': {}} if capabilities is None else capabilities
        self.server_requests = server_requests
        self.requests = []
        self.streams = []

    async def handle(self, request):
        body = json.loads(await request.aread()) if request.method == 'POST' else None
        self.requests.append((request, body))
        headers = {}
        if self.status:
            status, data = self.status, b'private server error'
            headers['location'] = 'https://127.0.0.1/private'
        elif request.method == 'DELETE':
            status, data = 204, b''
        elif request.method == 'GET':
            status, data = 405, b''
        elif body['method'] == 'initialize':
            result = {'protocolVersion': body['params']['protocolVersion'],
                      'capabilities': self.capabilities,
                      'serverInfo': {'name': 'fixture', 'version': '1'}}
            headers['mcp-session-id'] = 'test-session'
            status, data = self.result(body, result, headers)
        elif body['method'] == 'notifications/initialized':
            status, data = 202, b''
        elif body['method'] == 'tools/list':
            cursor = body.get('params', {}).get('cursor')
            status, data = self.result(body, self.pages[cursor], headers)
            if self.server_requests:
                requests = [
                    {'method': 'sampling/createMessage', 'id': 'sampling',
                     'params': {'messages': [], 'maxTokens': 1}},
                    {'method': 'elicitation/create', 'id': 'elicitation',
                     'params': {'message': 'Provide credentials',
                                'requestedSchema': {'type': 'object', 'properties': {}}}},
                    {'method': 'roots/list', 'id': 'roots'},
                ]
                data = b''.join(b'event: message\ndata: ' + json.dumps(
                    {'jsonrpc': '2.0', **item}).encode() + b'\n\n' for item in requests) + data
        else:
            raise AssertionError(f"Unexpected client method: {body}")
        stream = Chunks(data)
        self.streams.append(stream)
        return httpx.Response(status, headers=headers, stream=stream, request=request)

    def result(self, body, result, headers):
        data = json.dumps({'jsonrpc': '2.0', 'id': body['id'], 'result': result}).encode()
        headers['content-type'] = 'text/event-stream' if self.sse else 'application/json'
        if self.sse:
            data = b'event: message\ndata: ' + data + b'\n\n'
        return 200, data


class DiscoveryTests(unittest.TestCase):
    def run_fixture(self, fixture):
        with patch.object(discovery, 'public_address', AsyncMock(return_value=PUBLIC_IP)), \
             patch.object(httpx.AsyncHTTPTransport, 'handle_async_request', fixture.handle):
            return discovery.discover(URL)

    def test_paginated_json_and_sse_match_export(self):
        tools = copy.deepcopy(SUSPICIOUS['result']['tools'])
        tools[0].update({'vendor': {'nested': 'Keep exact metadata'},
                         '_meta': {'custom': 'preserved'},
                         'annotations': {'readOnlyHint': False}})
        exported = Inspector().inspect({'tools': tools})
        for sse in (False, True):
            with self.subTest(sse=sse):
                fixture = MCPFixture({None: {'tools': tools[:1], 'nextCursor': 'page2'},
                                      'page2': {'tools': tools[1:]}}, sse=sse)
                payload = self.run_fixture(fixture)
                self.assertEqual(payload, {'tools': tools})
                report = Inspector().inspect(payload)
                self.assertEqual(report.snapshot_hash, exported.snapshot_hash)
                self.assertEqual(report.findings, exported.findings)
                self.assertEqual(report.status, 'complete')
                self.assertTrue(all(stream.closed for stream in fixture.streams))
                self.assertTrue(any(r.method == 'DELETE' for r, _ in fixture.requests))
                for request, body in fixture.requests:
                    self.assertEqual(request.url.host, PUBLIC_IP)
                    self.assertEqual(request.headers['host'], 'weather.example')
                    self.assertEqual(request.extensions['sni_hostname'], 'weather.example')
                    self.assertEqual(request.headers['accept-encoding'], 'identity')
                    if body and body['method'] == 'tools/list':
                        self.assertEqual(request.headers['mcp-session-id'], 'test-session')
                        self.assertIn('mcp-protocol-version', request.headers)

    def test_cli_url_and_file_have_equal_findings(self):
        fixture = MCPFixture({None: SUSPICIOUS['result']})
        output = io.StringIO()
        with patch.object(discovery, 'public_address', AsyncMock(return_value=PUBLIC_IP)), \
             patch.object(httpx.AsyncHTTPTransport, 'handle_async_request', fixture.handle), \
             contextlib.redirect_stdout(output):
            code = main(['scan', URL, '--fail-on', 'high'])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())['snapshot_hash'],
                         Inspector().inspect(SUSPICIOUS).snapshot_hash)

    def test_empty_inventory_and_missing_tools_capability(self):
        self.assertEqual(self.run_fixture(MCPFixture({None: {'tools': []}})), {'tools': []})
        with self.assertRaisesRegex(discovery.DiscoveryError, 'does not advertise tools'):
            self.run_fixture(MCPFixture({}, capabilities={}))
        self.assertFalse(discovery._discovering.get())

    def test_server_requests_cannot_sample_elicit_or_read_roots(self):
        fixture = MCPFixture({None: {'tools': []}}, sse=True, server_requests=True)
        original = fixture.handle

        async def handle(transport, request):
            body = json.loads(await request.aread()) if request.method == 'POST' else None
            if body and 'method' not in body:
                fixture.requests.append((request, body))
                return httpx.Response(202, stream=Chunks(b''), request=request)
            return await original(request)

        fixture.handle = handle
        self.assertEqual(self.run_fixture(fixture), {'tools': []})
        replies = {b['id']: b for _, b in fixture.requests if b and 'method' not in b}
        self.assertEqual(set(replies), {'sampling', 'elicitation', 'roots'})
        self.assertTrue(all('error' in reply for reply in replies.values()))

    def test_repeated_cursor_and_page_limit_fail(self):
        fixture = MCPFixture({None: {'tools': [], 'nextCursor': 'again'},
                              'again': {'tools': [], 'nextCursor': 'again'}})
        with self.assertRaisesRegex(discovery.DiscoveryError, 'repeated'):
            self.run_fixture(fixture)
        with patch.object(discovery, 'MAX_PAGES', 1):
            with self.assertRaisesRegex(discovery.DiscoveryError, 'page limit'):
                self.run_fixture(fixture)

    def test_inventory_and_wire_limits(self):
        for limit, pattern in [('MAX_TOOLS', 'inventory'), ('MAX_BYTES', 'inventory'),
                               ('MAX_WIRE_BYTES', 'byte limit')]:
            with self.subTest(limit=limit), patch.object(discovery, limit, 0):
                with self.assertRaisesRegex(discovery.DiscoveryError, pattern):
                    self.run_fixture(MCPFixture({None: SUSPICIOUS['result']}))

    def test_later_page_failure_never_returns_partial_inventory(self):
        fixture = MCPFixture({None: {'tools': SUSPICIOUS['result']['tools'], 'nextCursor': 'bad'},
                              'bad': {'tools': 'invalid'}})
        with self.assertRaises(discovery.DiscoveryError):
            self.run_fixture(fixture)

    def test_http_errors_redirects_and_compression(self):
        for status in (301, 307, 401, 403, 500):
            with self.subTest(status=status):
                fixture = MCPFixture({}, status=status)
                with self.assertRaisesRegex(discovery.DiscoveryError,
                        'redirects' if status < 400 else f'HTTP {status}'):
                    self.run_fixture(fixture)
                self.assertEqual(len(fixture.requests), 1)
        async def compressed(transport, request):
            return httpx.Response(200, headers={'content-encoding': 'gzip'}, stream=Chunks(b''))
        with patch.object(httpx.AsyncHTTPTransport, 'handle_async_request', compressed), \
             patch.object(discovery, 'public_address', AsyncMock(return_value=PUBLIC_IP)):
            with self.assertRaisesRegex(discovery.DiscoveryError, 'Compressed'):
                discovery.discover(URL)

    def test_timeout_includes_dns_resolution(self):
        async def slow_dns(url):
            await asyncio.sleep(1)
        with patch.object(discovery, 'DISCOVERY_TIMEOUT', 0.01), \
             patch.object(discovery, 'public_address', slow_dns):
            with self.assertRaisesRegex(discovery.DiscoveryError, 'timed out'):
                discovery.discover(URL)

    def test_reject_invalid_urls_before_dns(self):
        for url in ('http://example.com/mcp', 'file:///tmp/tools', '', None, {},
                    'https://user:secret@example.com/mcp', 'https://example.com/mcp#fragment',
                    'https://[fe80::1%25en0]/mcp'):
            with self.subTest(url=url), patch.object(discovery, 'public_address') as resolver:
                with self.assertRaises(discovery.DiscoveryError):
                    discovery.discover(url)
                resolver.assert_not_called()

    def test_blocks_private_mixed_multicast_and_metadata_addresses(self):
        for ip in ('127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', 'fc00::1',
                   '::ffff:127.0.0.1', '224.0.0.1', '0.0.0.0'):
            records = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (PUBLIC_IP, 443)),
                       (socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443))]
            async def check():
                with patch.object(asyncio.get_running_loop(), 'getaddrinfo',
                                  AsyncMock(return_value=records)):
                    await discovery.public_address(httpx.URL(URL))
            with self.subTest(ip=ip), self.assertRaises(discovery.DiscoveryError):
                asyncio.run(check())

    def test_transport_cannot_switch_destinations(self):
        async def check():
            async with discovery.DiscoveryTransport(httpx.URL(URL), PUBLIC_IP) as transport:
                with patch.object(httpx.AsyncHTTPTransport, 'handle_async_request') as send:
                    with self.assertRaises(discovery.DiscoveryError):
                        await transport.handle_async_request(httpx.Request('POST', 'https://127.0.0.1/'))
                    send.assert_not_called()
        asyncio.run(check())

    def test_cli_errors_do_not_echo_server_details(self):
        fixture = MCPFixture({}, status=500)
        stderr = io.StringIO()
        with patch.object(discovery, 'public_address', AsyncMock(return_value=PUBLIC_IP)), \
             patch.object(httpx.AsyncHTTPTransport, 'handle_async_request', fixture.handle), \
             contextlib.redirect_stderr(stderr):
            self.assertEqual(main(['scan', URL]), 2)
        self.assertIn('HTTP 500', stderr.getvalue())
        self.assertNotIn('private server error', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
