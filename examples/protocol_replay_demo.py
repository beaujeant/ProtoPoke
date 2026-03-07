"""
Protocol-aware replay demo.

Captures a session, decodes all frames with a protocol definition, shows
a parsed summary, then lets you replay with field-level edits per message type.

Usage:
    # Terminal 1: start an echo server
    nc -lk 9090

    # Terminal 2: run this demo
    python examples/protocol_replay_demo.py examples/protocols/chat.proto.yaml

    # Terminal 3: connect, send a LoginRequest (binary), then Ctrl+D
    # (In practice you'd use a real client or craft bytes with Python)
"""

import asyncio
import logging
import sys

from protopoke.api import ProxyAPI
from protopoke.config import ProxyConfig
from protopoke.models import Direction
from protopoke.protocol.display import render_field_tree, render_frame_header

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)


async def wait_for_session(api: ProxyAPI, timeout: float = 120.0) -> str:
    elapsed = 0.0
    while elapsed < timeout:
        closed = [s for s in api.list_sessions() if not s.is_active()]
        if closed:
            return closed[-1].id
        await asyncio.sleep(0.2)
        elapsed += 0.2
    raise TimeoutError("No session captured within timeout")


def show_session(api: ProxyAPI, session_id: str) -> None:
    """Print a parsed summary of all captured frames."""
    msgs = api.decode_session_frames(session_id)
    print(f"\nCaptured {len(msgs)} frames:\n")
    for i, msg in enumerate(msgs):
        frame = msg.frame
        print(f"  [{i}] {render_frame_header(frame, msg).strip()}")
        print(render_field_tree(msg, width=72))


async def main() -> None:
    proto_path = sys.argv[1] if len(sys.argv) > 1 else None

    config = ProxyConfig(
        listen_host="127.0.0.1",
        listen_port=8080,
        upstream_host="127.0.0.1",
        upstream_port=9090,
        protocol_definition_path=proto_path,
    )

    api = ProxyAPI(config)
    await api.start()

    print(f"Proxy: 127.0.0.1:{config.listen_port} → "
          f"{config.upstream_host}:{config.upstream_port}")
    if proto_path:
        print(f"Protocol: {proto_path}")
    print("Waiting for a client session (Ctrl+D to close the client)...\n")

    try:
        session_id = await wait_for_session(api, timeout=120.0)
    except TimeoutError:
        print("Timed out waiting for session.")
        await api.stop()
        return

    show_session(api, session_id)

    # ── Replay 1: unmodified ─────────────────────────────────────────────────
    input("\nPress Enter to replay unmodified...")
    result = await api.replay_session(session_id)

    if result.success:
        print(f"Replay OK — sent {len(result.frames_sent())} frames, "
              f"received {len(result.frames_received())}")
        for f in result.frames_received():
            print(f"  ← [{f.sequence_number}] {f.raw_bytes!r}")
    else:
        print(f"Replay failed: {result.error}")

    # ── Replay 2: field-level edits ──────────────────────────────────────────
    if proto_path:
        print("\nField-level edit replay:")
        print("  Format: <MessageType>.<fieldname>=<value>")
        print("  Example: LoginRequest.username=hacker")
        print("  Leave blank to skip.\n")

        field_edits: dict[str, dict[str, object]] = {}
        while True:
            try:
                raw = input("  Edit (or Enter to replay): ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not raw:
                break
            if "." not in raw or "=" not in raw:
                print("  Format: <MessageType>.<field>=<value>")
                continue
            type_field, _, val_str = raw.partition("=")
            msg_type, _, field_name = type_field.partition(".")
            field_edits.setdefault(msg_type.strip(), {})[field_name.strip()] = val_str.strip()

        if field_edits:
            try:
                result2 = await api.replay_session_with_field_edits(
                    session_id=session_id,
                    field_edits=field_edits,
                )
                if result2.success:
                    print(f"\nField-edit replay OK — sent {len(result2.frames_sent())} frames")
                    for f in result2.frames_received():
                        print(f"  ← {f.raw_bytes!r}")
                else:
                    print(f"Field-edit replay failed: {result2.error}")
            except RuntimeError as exc:
                print(f"Error: {exc}")

    await api.stop()


if __name__ == "__main__":
    asyncio.run(main())
