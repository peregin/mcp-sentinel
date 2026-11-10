"""Bounded, public-HTTPS MCP discovery; target tools are never invoked."""
import asyncio
import ipaddress
import logging
import socket
from contextvars import ContextVar

import httpx
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client

from .engine import parse_payload
from .models import MAX_BYTES, MAX_TOOLS
from .scanner import canonical

DISCOVERY_TIMEOUT = 30
MAX_PAGES = 200
# Includes initialization, pagination envelopes, and optional server notifications.
MAX_WIRE_BYTES = MAX_BYTES * 2

# SDK parse errors can log raw metadata; silence them only in discovery's task context.
_discovering = ContextVar('sentinel_discovery', default=False)
for _name in ('mcp.client.streamable_http', 'mcp.shared.session', 'httpx', 'root'):
    logging.getLogger(_name).addFilter(lambda record: not _discovering.get())


class DiscoveryError(ValueError):
    """Safe, actionable error without server-controlled text or credentials."""


def validate_url(value):
    try:
        url = httpx.URL(value)
        if (url.scheme != 'https' or not url.host or url.userinfo or url.fragment
                or '%' in url.host):
            raise ValueError()
        return url
    except (TypeError, ValueError, httpx.InvalidURL):
        raise DiscoveryError('Use a public HTTPS MCP URL without embedded credentials or a fragment') from None


async def public_address(url):
    records = await asyncio.get_running_loop().getaddrinfo(
        url.host, url.port or 443, type=socket.SOCK_STREAM)
    addresses = [item[4][0] for item in records]
    if not addresses or any(not ipaddress.ip_address(ip).is_global
                            or ipaddress.ip_address(ip).is_multicast for ip in addresses):
        raise DiscoveryError('MCP URL must resolve only to public IP addresses')
    return addresses[0]


class LimitedStream(httpx.AsyncByteStream):
    def __init__(self, stream, transport):
        self.stream = stream
        self.transport = transport

    async def __aiter__(self):
        async for chunk in self.stream:
            self.transport.remaining -= len(chunk)
            if self.transport.remaining < 0:
                raise DiscoveryError('MCP response exceeds the discovery byte limit')
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


class DiscoveryTransport(httpx.AsyncHTTPTransport):
    def __init__(self, url, address):
        super().__init__(retries=0, trust_env=False)
        self.url = url
        self.address = address
        self.remaining = MAX_WIRE_BYTES

    async def handle_async_request(self, request):
        if request.url != self.url:
            raise DiscoveryError('MCP discovery cannot change the endpoint URL')
        # Connect to the validated numeric IP; retain the original Host and TLS identity.
        pinned = httpx.Request(request.method, request.url.copy_with(host=self.address),
            headers=request.headers, stream=request.stream,
            extensions={**request.extensions, 'sni_hostname': self.url.host})
        response = await super().handle_async_request(pinned)
        if 300 <= response.status_code < 400:
            await response.aclose()
            raise DiscoveryError('MCP redirects are not supported; use the final HTTPS endpoint URL')
        if response.headers.get('content-encoding', 'identity').lower() != 'identity':
            await response.aclose()
            raise DiscoveryError('Compressed MCP responses are not supported')
        response.stream = LimitedStream(response.stream, self)
        return response


async def discover_async(value):
    token = _discovering.set(True)
    try:
        url = validate_url(value)
        async with asyncio.timeout(DISCOVERY_TIMEOUT):
            address = await public_address(url)
            async with httpx.AsyncClient(transport=DiscoveryTransport(url, address),
                    timeout=10, trust_env=False, follow_redirects=False,
                    headers={'Accept-Encoding': 'identity'}) as client:
                async with streamable_http_client(str(url), http_client=client) as (read, write, _):
                    # Default callbacks reject sampling/elicitation and expose no local roots.
                    errors = []

                    async def on_message(message):
                        if isinstance(message, Exception):
                            errors.append(message)
                            await read.aclose()

                    try:
                        return await collect_tools(read, write, on_message)
                    except Exception:
                        if errors:
                            raise errors[0] from None
                        raise
    finally:
        _discovering.reset(token)


async def collect_tools(read, write, on_message):
    async with ClientSession(read, write, message_handler=on_message) as session:
        initialized = await session.initialize()
        if initialized.capabilities.tools is None:
            raise DiscoveryError('MCP server does not advertise tools')
        tools, seen = [], set()
        cursor = None
        for _ in range(MAX_PAGES):
            page = await session.list_tools(params=types.PaginatedRequestParams(cursor=cursor))
            tools.extend(tool.model_dump(mode='json', by_alias=True, exclude_unset=True)
                         for tool in page.tools)
            if len(tools) > MAX_TOOLS or len(canonical({'tools': tools}).encode()) > MAX_BYTES:
                raise DiscoveryError('MCP inventory exceeds 1 MB or 200 tools')
            cursor = page.nextCursor
            if not cursor:
                payload = {'tools': tools}
                parse_payload(payload)
                return payload
            if cursor in seen:
                raise DiscoveryError('MCP server repeated a pagination cursor')
            seen.add(cursor)
        raise DiscoveryError('MCP pagination exceeds the page limit')


def safe_error(exc):
    if isinstance(exc, DiscoveryError):
        return str(exc)
    if isinstance(exc, BaseExceptionGroup):
        for nested in exc.exceptions:
            message = safe_error(nested)
            if message:
                return message
    if isinstance(exc, TimeoutError):
        return 'MCP discovery timed out'
    if isinstance(exc, httpx.HTTPStatusError):
        return f'MCP endpoint returned HTTP {exc.response.status_code}'
    return None


def discover(value):
    try:
        return asyncio.run(discover_async(value))
    except Exception as exc:
        raise DiscoveryError(safe_error(exc) or
            'MCP discovery failed; check connectivity and Streamable HTTP support (authentication is not supported)') from None
