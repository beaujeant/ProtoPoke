"""
Session replay demo.

Shows how to capture a session and replay it with optional modifications.

Usage:
    # Terminal 1: start an echo server
    nc -lk 9090

    # Terminal 2: start the replay demo
    python examples/replay_demo.py

    # Terminal 3: connect and send something
    nc 127.0.0.1 8080
    hello world    (then Ctrl+D)

    # Back in Terminal 2: hit Enter to replay the captured session.
"""

import asyncio
import sys
import logging

from tcpproxy.api import ProxyAPI
from tcpproxy.config import ProxyConfig
from tcpproxy.models import Direction

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)


async def wait_for_session(api: ProxyAPI, timeout: float = 60.0) -> str:
    """Wait until at least one session is fully closed."""
    elapsed = 0.0
    while elapsed < timeout:
        closed = [s for s in api.list_sessions() if not s.is_active()]
        if closed:
            return closed[-1].id
        await asyncio.sleep(0.2)
        elapsed += 0.2
    raise TimeoutError("No session captured within timeout")


async def main() -> None:
    config = ProxyConfig(
        listen_host="127.0.0.1",
        listen_port=8080,
        upstream_host="127.0.0.1",
        upstream_port=9090,
    )
    api = ProxyAPI(config)
    await api.start()

    print(f"Proxy: 127.0.0.1:{config.listen_port} → "
          f"{config.upstream_host}:{config.upstream_port}")
    print("Waiting for a client connection (then Ctrl+D to close)...\n")

    try:
        session_id = await wait_for_session(api, timeout=120.0)
    except TimeoutError:
        print("Timed out waiting for session.")
        await api.stop()
        return

    session = api.get_session(session_id)
    frames = api.get_frames(session_id)
    client_frames = [f for f in frames if f.direction is Direction.CLIENT_TO_SERVER]

    print(f"Captured session {session_id[:8]}")
    print(f"  Total frames:  {len(frames)}")
    print(f"  Client frames: {len(client_frames)}")
    for i, f in enumerate(client_frames):
        print(f"  [{i}] seq={f.sequence_number} len={len(f.raw_bytes)}  {f.raw_bytes[:48]!r}")

    print()
    input("Press Enter to replay the session (unmodified)...")

    result = await api.replay_session(session_id)

    if result.success:
        print(f"\nReplay successful!")
        print(f"  Sent {len(result.client_frames_sent())} frames "
              f"({result.total_bytes_sent()} bytes)")
        print(f"  Received {len(result.server_frames_received())} frames "
              f"({result.total_bytes_received()} bytes)")
        for f in result.server_frames_received():
            print(f"  ← {f.raw_bytes!r}")
    else:
        print(f"\nReplay failed: {result.error}")

    # Optional: replay with a modification
    if client_frames:
        print()
        answer = input("Replay with first frame modified? [y/N]: ").strip().lower()
        if answer == "y":
            new_data = input("  Enter new bytes for first frame: ").encode()
            modified = {client_frames[0].id: new_data}
            result2 = await api.replay_session(session_id, modified_frames=modified)
            if result2.success:
                print("  Modified replay successful!")
                for f in result2.server_frames_received():
                    print(f"  ← {f.raw_bytes!r}")
            else:
                print(f"  Failed: {result2.error}")

    await api.stop()


if __name__ == "__main__":
    asyncio.run(main())
