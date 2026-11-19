from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import pytest

from backend.agent import __main__ as agent_cli
from backend.infrastructure.transport.http.client import (
    EnrollmentGrant, HttpAgentEnrollmentClient, HttpTransportConfig, HttpTransportError,
)


def _grant(**changes):
    result = {
        "endpoint_id": str(uuid4()), "credential_id": str(uuid4()),
        "credential_secret": "s" * 48, "organization_id": str(uuid4()),
        "protocol_version": "1.0", "status": "new",
        "credential_expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }
    result.update(changes)
    return result


def test_enrollment_uses_header_only_and_accepts_finite_pending_grant():
    observed = {}

    def respond(request):
        observed["request"] = request
        return httpx.Response(201, json=_grant(), headers={"Cache-Control": "no-store"})

    client = HttpAgentEnrollmentClient(
        HttpTransportConfig("https://control.example", verify=True),
        client=httpx.Client(transport=httpx.MockTransport(respond)),
    )
    token = "bootstrap-private-token"
    grant = client.enroll(
        enrollment_id=str(uuid4()), bootstrap_token=token,
        hostname="workstation-01", platform_name="Windows", platform_version="11",
        architecture="AMD64", agent_version="1.0.0", protocol_version="1.0",
        request_id=str(uuid4()), nonce=uuid4().hex,
    )
    assert isinstance(grant, EnrollmentGrant)
    assert grant.status == "new"
    assert observed["request"].headers["authorization"] == f"Bearer {token}"
    assert token not in observed["request"].content.decode()
    assert "organization_id" not in observed["request"].content.decode()
    assert token not in repr(grant)


@pytest.mark.parametrize("response", [
    _grant(credential_expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()),
    _grant(credential_expires_at=(datetime.now(timezone.utc) + timedelta(days=90)).isoformat()),
    _grant(status="approved"),
    _grant(credential_secret="short"),
])
def test_enrollment_rejects_malformed_or_unbounded_grant(response):
    client = HttpAgentEnrollmentClient(
        HttpTransportConfig("https://control.example"),
        client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(201, json=response))),
    )
    with pytest.raises(HttpTransportError) as error:
        client.enroll(enrollment_id=str(uuid4()), bootstrap_token="secret", hostname="h",
                      platform_name="Windows", platform_version=None, architecture=None,
                      agent_version="1", protocol_version="1.0")
    assert error.value.code == "invalid_response"


def test_enrollment_failure_does_not_echo_remote_body_or_token():
    client = HttpAgentEnrollmentClient(
        HttpTransportConfig("https://control.example"),
        client=httpx.Client(transport=httpx.MockTransport(
            lambda _: httpx.Response(401, text="secret-from-server"))),
    )
    with pytest.raises(HttpTransportError) as error:
        client.enroll(enrollment_id=str(uuid4()), bootstrap_token="bootstrap-secret", hostname="h",
                      platform_name="Windows", platform_version=None, architecture=None,
                      agent_version="1", protocol_version="1.0")
    assert error.value.code == "enrollment_rejected"
    assert "secret" not in str(error.value)


def test_installer_can_replace_a_rejected_token_pair(monkeypatch, capsys):
    first_id, new_id = str(uuid4()), str(uuid4())
    first_token, new_token = "old-private-token", "fresh-private-token"
    inputs = iter((first_token, new_id, new_token))
    monkeypatch.setattr(agent_cli, "_read_hidden", lambda _: next(inputs))
    submissions = []

    def respond(request):
        submissions.append((request.headers["x-raven-enrollment-id"], request.headers["authorization"]))
        if len(submissions) == 1:
            return httpx.Response(401, json={"error": "enrollment_rejected"})
        return httpx.Response(201, json=_grant())

    with httpx.Client(transport=httpx.MockTransport(respond)) as http:
        client = HttpAgentEnrollmentClient(HttpTransportConfig("https://control.example"), client=http)
        grant = agent_cli._request_enrollment(client, first_id, token_stdin=False, interactive_retry=True)

    assert grant.status == "new"
    assert submissions == [(first_id, f"Bearer {first_token}"), (new_id, f"Bearer {new_token}")]
    captured = capsys.readouterr()
    assert first_token not in captured.out + captured.err
    assert new_token not in captured.out + captured.err


@pytest.mark.parametrize("status,attempts", [(401, 3), (429, 1), (503, 1)])
def test_only_definite_rejections_offer_a_bounded_retry(monkeypatch, status, attempts):
    inputs = iter(("private-token", "", "private-token", "", "private-token"))
    monkeypatch.setattr(agent_cli, "_read_hidden", lambda _: next(inputs))
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(status)

    with httpx.Client(transport=httpx.MockTransport(respond)) as http:
        client = HttpAgentEnrollmentClient(HttpTransportConfig("https://control.example"), client=http)
        with pytest.raises(HttpTransportError) as error:
            agent_cli._request_enrollment(client, str(uuid4()), token_stdin=False, interactive_retry=True)

    assert error.value.status_code == status
    assert len(requests) == attempts
    assert len({request.read() for request in requests}) == attempts
