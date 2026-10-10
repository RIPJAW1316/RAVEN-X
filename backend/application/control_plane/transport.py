"""In-process duplex transport; no sockets or network behavior."""

from datetime import datetime, timezone

from ...application.ports.agent_transport import PresentedCredential


class InProcessDuplexTransport:
    def __init__(self, control_processor):
        self._control_processor = control_processor
        self._agents = {}
        self.control_to_agent = []
        self.agent_to_control = []

    def attach_agent(self, agent) -> None:
        endpoint_id = agent.endpoint_id
        if endpoint_id is None:
            raise ValueError("an enrolled agent identity is required")
        if endpoint_id in self._agents:
            raise ValueError(f"an agent is already attached for {endpoint_id}")
        self._agents[endpoint_id] = agent

    def send_control_to_agent(self, envelope):
        agent = self._agents.get(envelope.endpoint_id)
        if agent is None:
            raise RuntimeError(f"no agent is attached for {envelope.endpoint_id}")
        self.control_to_agent.append(envelope)
        return agent.receive(envelope)

    def send(self, envelope) -> None:
        """AgentMessageSender implementation for agent-to-control traffic."""
        agent = self._agents.get(envelope.endpoint_id)
        if agent is None:
            raise RuntimeError(f"no agent is attached for {envelope.endpoint_id}")
        credential = agent.credential_store.load()
        if credential is None:
            raise RuntimeError("agent has no credential")
        self.agent_to_control.append(envelope)
        self._control_processor.process(
            envelope,
            PresentedCredential(credential.secret, credential_id=credential.credential_id),
            now=datetime.now(timezone.utc),
        )
