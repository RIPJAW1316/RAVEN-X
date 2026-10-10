from importlib import import_module


_EXPORTS = {
    "HttpAgentTransport": (".client", "HttpAgentTransport"),
    "HttpTransportConfig": (".client", "HttpTransportConfig"),
    "HttpTransportError": (".client", "HttpTransportError"),
    "LeasedHttpWork": (".client", "LeasedHttpWork"),
    "HttpControlPlaneTransport": (".outbox", "HttpControlPlaneTransport"),
    "PendingWorkQueue": (".outbox", "PendingWorkQueue"),
    "create_agent_http_app": (".server", "create_agent_http_app"),
    "create_agent_http_router": (".server", "create_agent_http_router"),
}


def __getattr__(name):
    try:
        module_name, attribute = _EXPORTS[name]
    except KeyError as error:
        raise AttributeError(name) from error
    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value

__all__ = [
    "HttpAgentTransport",
    "HttpTransportConfig",
    "HttpTransportError",
    "LeasedHttpWork",
    "HttpControlPlaneTransport",
    "PendingWorkQueue",
    "create_agent_http_app",
    "create_agent_http_router",
]
