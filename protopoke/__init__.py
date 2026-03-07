"""
ProtoPoke — a personal TCP interception and replay tool.

High-level entry point: use protopoke.api.ProxyAPI to control everything.

    from protopoke.config import ProxyConfig
    from protopoke.api import ProxyAPI

    config = ProxyConfig(listen_port=8080, upstream_host="...", upstream_port=9090)
    api = ProxyAPI(config)
    await api.start()
"""
