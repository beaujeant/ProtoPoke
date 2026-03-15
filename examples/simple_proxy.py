"""
Simple passthrough proxy example.

Starts a proxy and prints every captured frame to stdout.
No interception — traffic flows through unmodified.

Usage:
    python examples/simple_proxy.py

    # In another terminal:
    nc 127.0.0.1 8080    # connects through the proxy to 127.0.0.1:9090

    # Or point your application at 127.0.0.1:8080 instead of the real server.

To customise:
    - Change listen_port, upstream_host, upstream_port below.
    - Set framer_name="delimiter" or "length_prefix" for framing.
    - Add more event handlers (on_session_opened, on_session_closed).
"""

import asyncio
import logging
import sys

from protopoke.api import ProxyAPI
from protopoke.config import ProxyConfig
from protopoke.events.bus import FrameCapturedEvent, SessionOpenedEvent, SessionClosedEvent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("simple_proxy")


async def main() -> None:
    config = ProxyConfig(
        listen_host="127.0.0.1",
        listen_port=8080,
        upstream_host="127.0.0.1",
        upstream_port=9090,
        tamper_enabled=False,
        # Change to "delimiter" for line-based protocols:
        # framer_name="delimiter",
        # framer_kwargs={"delimiter": b"\n"},
    )

    api = ProxyAPI(config)

    async def on_session_open(event: SessionOpenedEvent) -> None:
        s = event.session
        print(f"\n[+] Session opened: {s.id[:8]}  "
              f"client={s.client_host}:{s.client_port}  "
              f"server={s.server_host}:{s.server_port}")

    async def on_session_close(event: SessionClosedEvent) -> None:
        s = event.session
        print(f"\n[-] Session closed: {s.id[:8]}")

    async def on_frame(event: FrameCapturedEvent) -> None:
        f  = event.frame
        arrow = "→" if f.direction.value == "client_to_server" else "←"
        print(
            f"  [{f.session_id[:8]}] {arrow} "
            f"seq={f.sequence_number:3d}  "
            f"len={len(f.raw_bytes):5d}  "
            f"{f.raw_bytes[:64]!r}"
            + ("..." if len(f.raw_bytes) > 64 else "")
        )

    api.on_session_opened(on_session_open)
    api.on_session_closed(on_session_close)
    api.on_frame_captured(on_frame)

    print(f"Proxy: 127.0.0.1:{config.listen_port} → "
          f"{config.upstream_host}:{config.upstream_port}")
    print("Press Ctrl+C to stop.\n")

    try:
        await api.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        await api.stop()
        sessions = api.list_sessions()
        print(f"\nTotal sessions: {len(sessions)}")
        for s in sessions:
            frames = api.get_frames(s.id)
            print(f"  {s.id[:8]}  frames={len(frames)}")


if __name__ == "__main__":
    asyncio.run(main())
