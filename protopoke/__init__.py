"""
ProtoPoke — a personal TCP interception and replay tool.

High-level entry point: use protopoke.api.ProtoPokeAPI to control everything.

    from protopoke.config import ForwarderConfig
    from protopoke.api import ProtoPokeAPI

    fwd = ForwarderConfig(name="Default", listen_port=8080, upstream_host="...", upstream_port=9090)
    api = ProtoPokeAPI([fwd])
    await api.start()
"""
