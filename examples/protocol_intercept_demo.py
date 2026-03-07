"""
Protocol-aware interception demo.

Like intercept_demo.py, but loads a protocol definition so intercepted
frames are displayed as a Wireshark-style field tree + hex dump, and the
operator can edit individual fields by name.

Usage:
    # Terminal 1: start an echo server (or real server)
    nc -lk 9090

    # Terminal 2: run this demo with a protocol definition
    python examples/protocol_intercept_demo.py examples/protocols/chat.proto.yaml

    # Terminal 3: connect and send binary data
    nc 127.0.0.1 8080

Commands when a frame is intercepted:
    f               Forward as-is.
    d               Drop.
    e <field>=<val> Edit a field and forward (e.g. "e username=hacker").
    x <hex>         Replace the whole frame with raw hex bytes.
    m <text>        Replace the whole frame with ASCII text.
    ?               Show the frame again.
    q               Quit.
"""

import asyncio
import logging
import sys
from pathlib import Path

from protopoke.api import ProxyAPI
from protopoke.config import ProxyConfig
from protopoke.models import InterceptedUnit, ParsedMessage
from protopoke.protocol.display import (
    render_field_tree,
    render_frame_header,
    render_hexdump,
    highlights_from_message,
)

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)


def print_parsed_frame(unit: InterceptedUnit, msg: ParsedMessage) -> None:
    """Print the full Wireshark-style view of an intercepted frame."""
    print(f"\n{'═' * 72}")
    print(render_frame_header(unit.frame, msg))
    print()
    print(render_field_tree(msg, width=72))
    print(render_hexdump(
        unit.frame.raw_bytes,
        highlights=highlights_from_message(msg),
        width=16,
    ))


def parse_field_edit(raw: str) -> tuple[str, str] | None:
    """Parse 'e fieldname=value' into (fieldname, value). Returns None on error."""
    body = raw[2:].strip()
    if "=" not in body:
        return None
    name, _, value = body.partition("=")
    return name.strip(), value.strip()


def coerce_field_value(value_str: str, current_value) -> object:
    """
    Try to coerce the user's string input to the type of the current field value.

    - If current is int: try int parse (hex or decimal).
    - If current is bytes: try hex decode.
    - Otherwise: return as string.
    """
    if isinstance(current_value, int):
        try:
            return int(value_str, 0)   # handles "0x10", "16", "0b1010"
        except ValueError:
            return value_str
    if isinstance(current_value, bytes):
        try:
            return bytes.fromhex(value_str.replace(" ", ""))
        except ValueError:
            return value_str.encode()
    return value_str


async def intercept_loop(api: ProxyAPI, stop_event: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()

    while not stop_event.is_set():
        try:
            unit, msg = await asyncio.wait_for(
                api.get_next_intercepted_parsed(), timeout=1.0
            )
        except asyncio.TimeoutError:
            continue

        print_parsed_frame(unit, msg)

        while True:
            try:
                raw = await loop.run_in_executor(
                    None,
                    lambda: input(
                        "  Action [f=forward  d=drop  e <field>=<val>  "
                        "x <hex>  m <text>  ?=show  q=quit]: "
                    ).strip(),
                )
            except (EOFError, KeyboardInterrupt):
                api.forward(unit.id)
                stop_event.set()
                return

            if raw == "f":
                api.forward(unit.id)
                print("  → Forwarded")
                break

            elif raw == "d":
                api.drop(unit.id)
                print("  → Dropped")
                break

            elif raw == "q":
                api.forward(unit.id)
                stop_event.set()
                return

            elif raw == "?":
                print_parsed_frame(unit, msg)

            elif raw.startswith("e "):
                parsed = parse_field_edit(raw)
                if parsed is None:
                    print("  Usage: e <fieldname>=<value>")
                    continue
                field_name, value_str = parsed

                # Find current value for type coercion
                pf = msg.field_by_name(field_name)
                if pf is None:
                    available = [f.name for f in msg.fields]
                    print(f"  Field {field_name!r} not found. Available: {available}")
                    continue

                coerced = coerce_field_value(value_str, pf.value)
                ok = api.modify_field_and_forward(unit.id, {field_name: coerced})
                if ok:
                    print(f"  → Forwarded with {field_name}={coerced!r}")
                    break
                else:
                    print(
                        "  Field edit failed (no encoder? field already forwarded?). "
                        "Try 'f' or 'x'."
                    )

            elif raw.startswith("x "):
                try:
                    new_data = bytes.fromhex(raw[2:].replace(" ", ""))
                    api.modify_and_forward(unit.id, new_data)
                    print(f"  → Forwarded hex edit ({len(new_data)} bytes)")
                    break
                except ValueError as exc:
                    print(f"  Invalid hex: {exc}")

            elif raw.startswith("m "):
                new_data = raw[2:].encode()
                api.modify_and_forward(unit.id, new_data)
                print(f"  → Forwarded modified: {new_data!r}")
                break

            else:
                print(
                    "  Commands: f=forward  d=drop  "
                    "e <field>=<val>  x <hex>  m <text>  ?=show  q=quit"
                )


async def main() -> None:
    proto_path = sys.argv[1] if len(sys.argv) > 1 else None

    config = ProxyConfig(
        listen_host="127.0.0.1",
        listen_port=8080,
        upstream_host="127.0.0.1",
        upstream_port=9090,
        intercept_enabled=True,
        framer_name="raw",
        protocol_definition_path=proto_path,
    )

    api = ProxyAPI(config)
    stop_event = asyncio.Event()

    if proto_path:
        print(f"Protocol: {proto_path}")
    else:
        print("Protocol: none (passthrough decoder — raw hex display)")

    print(f"Proxy: 127.0.0.1:{config.listen_port} → "
          f"{config.upstream_host}:{config.upstream_port}")
    print("Intercept ON. Connect a client to 127.0.0.1:8080. Ctrl+C to stop.\n")

    await api.start()

    intercept_task = asyncio.create_task(intercept_loop(api, stop_event))

    try:
        await stop_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        intercept_task.cancel()
        try:
            await intercept_task
        except (asyncio.CancelledError, Exception):
            pass

        await api.stop()

        sessions = api.list_sessions()
        print(f"\n{'═' * 72}")
        print(f"Sessions captured: {len(sessions)}")
        for s in sessions:
            frames = api.get_frames(s.id)
            msgs = api.decode_session_frames(s.id)
            types = [m.message_type for m in msgs if m.message_type not in ("", "<unknown>")]
            print(f"  {s.id[:8]}  frames={len(frames)}  types={types}")


if __name__ == "__main__":
    asyncio.run(main())
