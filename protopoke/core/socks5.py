"""
SOCKS5 wire protocol — RFC 1928 + RFC 1929 (user/pass auth).

Pure protocol module: no socket I/O beyond reading/writing through asyncio
streams the caller passes in. The caller is responsible for opening the
upstream connection and sending the success/failure reply.

Supported:
    - Auth methods: no-auth (0x00) and username/password (0x02).
    - Commands: CONNECT (0x01) only. BIND and UDP ASSOCIATE return
      0x07 (Command not supported).
    - Address types: IPv4 (0x01), domain name (0x03), IPv6 (0x04).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import struct
from enum import IntEnum
from typing import Optional

logger = logging.getLogger(__name__)


SOCKS_VERSION = 0x05

# Auth methods
AUTH_NONE        = 0x00
AUTH_USERPASS    = 0x02
AUTH_NO_ACCEPTABLE = 0xFF

# Commands
CMD_CONNECT       = 0x01
CMD_BIND          = 0x02
CMD_UDP_ASSOCIATE = 0x03

# Address types
ATYP_IPV4   = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6   = 0x04


class Socks5Reply(IntEnum):
    """RFC 1928 reply codes (REP field)."""
    SUCCEEDED                 = 0x00
    GENERAL_FAILURE           = 0x01
    CONN_NOT_ALLOWED          = 0x02
    NETWORK_UNREACHABLE       = 0x03
    HOST_UNREACHABLE          = 0x04
    CONNECTION_REFUSED        = 0x05
    TTL_EXPIRED               = 0x06
    COMMAND_NOT_SUPPORTED     = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class Socks5Error(Exception):
    """Raised when the SOCKS5 handshake cannot complete."""

    def __init__(self, message: str, reply: Socks5Reply = Socks5Reply.GENERAL_FAILURE) -> None:
        super().__init__(message)
        self.reply = reply


def reply_for_oserror(exc: OSError) -> Socks5Reply:
    """Map a socket OSError to the closest SOCKS5 reply code."""
    if isinstance(exc, ConnectionRefusedError):
        return Socks5Reply.CONNECTION_REFUSED
    err = getattr(exc, "errno", None)
    if err in (socket.EAI_NONAME, socket.EAI_NODATA):  # type: ignore[attr-defined]
        return Socks5Reply.HOST_UNREACHABLE
    return Socks5Reply.GENERAL_FAILURE


async def negotiate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    auth_user: Optional[str],
    auth_pass: Optional[str],
) -> tuple[str, int]:
    """
    Perform the SOCKS5 client→server handshake up to (but not including) the
    final reply. The caller is responsible for opening the upstream connection
    and then calling :func:`send_reply` with the result.

    Returns the parsed ``(target_host, target_port)`` from the CONNECT request.

    Raises ``Socks5Error`` for protocol violations or unsupported features.
    """
    # 1. Greeting:  VER NMETHODS METHODS...
    header = await reader.readexactly(2)
    if header[0] != SOCKS_VERSION:
        raise Socks5Error(
            f"Unsupported SOCKS version 0x{header[0]:02x}",
            Socks5Reply.GENERAL_FAILURE,
        )
    nmethods = header[1]
    methods = await reader.readexactly(nmethods) if nmethods else b""

    # 2. Method selection
    require_auth = auth_user is not None
    chosen = AUTH_USERPASS if require_auth else AUTH_NONE
    if chosen not in methods:
        writer.write(bytes([SOCKS_VERSION, AUTH_NO_ACCEPTABLE]))
        await writer.drain()
        raise Socks5Error(
            "Client did not offer the required auth method",
            Socks5Reply.CONN_NOT_ALLOWED,
        )
    writer.write(bytes([SOCKS_VERSION, chosen]))
    await writer.drain()

    # 3. Optional user/pass sub-negotiation (RFC 1929)
    if require_auth:
        await _userpass_subnegotiate(reader, writer, auth_user or "", auth_pass or "")

    # 4. Request:  VER CMD RSV ATYP DST.ADDR DST.PORT
    request_header = await reader.readexactly(4)
    ver, cmd, _rsv, atyp = request_header
    if ver != SOCKS_VERSION:
        raise Socks5Error(
            "Bad version in request",
            Socks5Reply.GENERAL_FAILURE,
        )
    if cmd != CMD_CONNECT:
        raise Socks5Error(
            f"Command 0x{cmd:02x} not supported",
            Socks5Reply.COMMAND_NOT_SUPPORTED,
        )

    target_host = await _read_address(reader, atyp)
    port_bytes = await reader.readexactly(2)
    target_port = struct.unpack("!H", port_bytes)[0]

    return target_host, target_port


async def _userpass_subnegotiate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    expected_username: str,
    expected_password: str,
) -> None:
    """RFC 1929 username/password sub-negotiation."""
    ver_byte = await reader.readexactly(1)
    if ver_byte[0] != 0x01:
        raise Socks5Error(
            f"Unsupported user/pass auth version 0x{ver_byte[0]:02x}",
            Socks5Reply.CONN_NOT_ALLOWED,
        )
    username_length = (await reader.readexactly(1))[0]
    username = (await reader.readexactly(username_length)).decode("utf-8", errors="replace")
    password_length = (await reader.readexactly(1))[0]
    password = (await reader.readexactly(password_length)).decode("utf-8", errors="replace")

    if username == expected_username and password == expected_password:
        writer.write(bytes([0x01, 0x00]))
        await writer.drain()
        return

    writer.write(bytes([0x01, 0x01]))
    await writer.drain()
    raise Socks5Error("Invalid SOCKS5 credentials", Socks5Reply.CONN_NOT_ALLOWED)


async def _read_address(reader: asyncio.StreamReader, atyp: int) -> str:
    """Read DST.ADDR for the given ATYP and return the host as a string."""
    if atyp == ATYP_IPV4:
        raw = await reader.readexactly(4)
        return str(ipaddress.IPv4Address(raw))
    if atyp == ATYP_IPV6:
        raw = await reader.readexactly(16)
        return str(ipaddress.IPv6Address(raw))
    if atyp == ATYP_DOMAIN:
        domain_length = (await reader.readexactly(1))[0]
        return (await reader.readexactly(domain_length)).decode("ascii", errors="replace")
    raise Socks5Error(
        f"Unknown ATYP 0x{atyp:02x}",
        Socks5Reply.ADDRESS_TYPE_NOT_SUPPORTED,
    )


def _encode_address(host: str, port: int) -> bytes:
    """Encode an address as ATYP + ADDR + PORT."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        host_bytes = host.encode("ascii", errors="replace")
        if len(host_bytes) > 255:
            host_bytes = host_bytes[:255]
        return bytes([ATYP_DOMAIN, len(host_bytes)]) + host_bytes + struct.pack("!H", port)
    if isinstance(addr, ipaddress.IPv4Address):
        return bytes([ATYP_IPV4]) + addr.packed + struct.pack("!H", port)
    return bytes([ATYP_IPV6]) + addr.packed + struct.pack("!H", port)


async def send_reply(
    writer: asyncio.StreamWriter,
    reply: Socks5Reply,
    bnd_host: str = "0.0.0.0",
    bnd_port: int = 0,
) -> None:
    """
    Send a SOCKS5 reply.

    ``bnd_host``/``bnd_port`` should be the local end of the upstream socket on
    success (commonly ``writer.get_extra_info('sockname')``); 0.0.0.0:0 is
    acceptable for failure replies.
    """
    payload = bytes([SOCKS_VERSION, int(reply), 0x00]) + _encode_address(bnd_host, bnd_port)
    writer.write(payload)
    try:
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
