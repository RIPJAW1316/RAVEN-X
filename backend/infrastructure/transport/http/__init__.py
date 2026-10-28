from importlib import import_module


_EXPORTS = {
    "EnrollmentGrant": (".client", "EnrollmentGrant"),
    "HttpAgentEnrollmentClient": (".client", "HttpAgentEnrollmentClient"),
    "HttpAgentTransport": (".client", "HttpAgentTransport"),
    "HttpTransportConfig": (".client", "HttpTransportConfig"),
    "HttpTransportError": (".client", "HttpTransportError"),
    "LeasedHttpWork": (".client", "LeasedHttpWork"),
    "RenewalConfirmation": (".client", "RenewalConfirmation"),
    "RenewalReceipt": (".client", "RenewalReceipt"),
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
    "EnrollmentGrant",
    "HttpAgentEnrollmentClient",
    "HttpAgentTransport",
    "HttpTransportConfig",
    "HttpTransportError",
    "LeasedHttpWork",
    "RenewalConfirmation",
    "RenewalReceipt",
    "HttpControlPlaneTransport",
    "PendingWorkQueue",
    "create_agent_http_app",
    "create_agent_http_router",
]
