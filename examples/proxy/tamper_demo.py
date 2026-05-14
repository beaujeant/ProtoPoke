"""
Interactive interception demo.

Starts the proxy with interception enabled. For each intercepted frame,
you can choose to forward, drop, or modify it from the command line.

This is a minimal demonstration of the interception API. A real UI would
wrap the same ProtoPokeAPI calls in a graphical interface.

Usage:
    python examples/proxy/tamper_demo.py

    # In another terminal:
    nc 127.0.0.1 8080

    # Then type in the nc window; each line will be intercepted.

Commands when a frame is intercepted:
    f           Forward the frame as-is.
    d           Drop the frame.
    m <data>    Forward with modified content (e.g: m hello world).
    x           Hex edit — enter hex bytes (e.g: 48 65 6c 6c 6f).
    ?           Show the frame again.
"""

import asyncio
import logging
import sys

from protopoke.api import ProtoPokeAPI
from protopoke.config import ForwarderConfig
from protopoke.models import TamperedUnit

logging.basicConfig(
    level=logging.WARNING,  # Quieter for interactive use
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    stream=sys.stderr,
)


def print_unit(unit: TamperedUnit) -> None:
    frame = unit.frame
    arrow = "→" if frame.direction.value == "client_to_server" else "←"
    print(f"\n{'─'*60}")
    print(f"  Intercepted: {unit.id[:8]}")
    print(f"  Session:     {frame.session_id[:8]}")
    print(f"  Direction:   {arrow}  {frame.direction.value}")
    print(f"  Length:      {len(frame.raw_bytes)} bytes")
    print(f"  Repr:        {frame.raw_bytes!r}")
    print(f"  Hex:         {frame.raw_bytes.hex()}")
    print(f"{'─'*60}")


async def intercept_loop(api: ProtoPokeAPI, stop_event: asyncio.Event) -> None:
    """Process the intercept queue until stop_event is set."""
    loop = asyncio.get_running_loop()

    while not stop_event.is_set():
        try:
            unit = await asyncio.wait_for(api.get_next_intercepted(), timeout=1.0)
        except asyncio.TimeoutError:
            continue  # Check stop_event and try again

        print_unit(unit)
        current_unit = unit  # for the '?' command

        while True:
            try:
                # Read input without blocking the event loop
                raw = await loop.run_in_executor(
                    None,
                    lambda: input("  Action [f/d/m <data>/x <hex>/? for help]: ").strip(),
                )
            except (EOFError, KeyboardInterrupt):
                # EOF or Ctrl+C during input: forward and stop
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

            elif raw.startswith("m "):
                new_data = raw[2:].encode()
                api.modify_and_forward(unit.id, new_data)
                print(f"  → Forwarded modified ({len(new_data)} bytes): {new_data!r}")
                break

            elif raw.startswith("x "):
                try:
                    hex_str = raw[2:].replace(" ", "")
                    new_data = bytes.fromhex(hex_str)
                    api.modify_and_forward(unit.id, new_data)
                    print(f"  → Forwarded hex edit ({len(new_data)} bytes): {new_data.hex()}")
                    break
                except ValueError as e:
                    print(f"  Invalid hex: {e}")

            elif raw == "?":
                print_unit(current_unit)

            else:
                print("  Commands: f=forward  d=drop  m <text>=modify  x <hex>=hex edit  ?=show again")


async def main() -> None:
    config = ForwarderConfig(
        name="Default",
        listen_host="127.0.0.1",
        listen_port=8080,
        upstream_host="127.0.0.1",
        upstream_port=9090,
        tamper_enabled=True,
        framer_name="raw",  # Raw framer: each read chunk = one frame
    )

    api = ProtoPokeAPI([config])
    stop_event = asyncio.Event()

    print(f"Proxy with interception: 127.0.0.1:{config.listen_port} "
          f"→ {config.upstream_host}:{config.upstream_port}")
    print("Intercept is ON. Connect a client to 127.0.0.1:8080.")
    print("Press Ctrl+C to stop.\n")

    await api.start()

    intercept_task = asyncio.create_task(intercept_loop(api, stop_event))

    try:
        # Wait for stop signal (Ctrl+C or EOF in intercept loop)
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
        print(f"\n{'═'*60}")
        print(f"Sessions captured: {len(sessions)}")
        for s in sessions:
            frames = api.get_frames(s.id)
            print(f"  {s.id[:8]}  client={s.info.client_host}:{s.info.client_port}  "
                  f"frames={len(frames)}")


if __name__ == "__main__":
    asyncio.run(main())
