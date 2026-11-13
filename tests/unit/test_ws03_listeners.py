import ipaddress
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest

from backend.application.ops.listeners import bind_sockets, validated_hosts
from backend.cli import generate_local_tls


def _cert(tmp_path: Path) -> Path:
    result = generate_local_tls(tmp_path / "tls", ["192.168.1.121"],
                                protect=lambda path: path.mkdir(parents=True))
    return Path(result["server.pem"])


def test_loopback_and_lan_share_one_validated_certificate(tmp_path):
    cert = _cert(tmp_path)
    assert validated_hosts(["127.0.0.1", "192.168.1.121"], cert) == (
        "127.0.0.1", "192.168.1.121")
    assert validated_hosts(["192.168.1.121"], cert) == ("192.168.1.121",)
    assert ipaddress.ip_address("127.0.0.1") != ipaddress.ip_address("192.168.1.121")


@pytest.mark.parametrize("hosts", [
    ["0.0.0.0"], ["localhost"],
    ["127.0.0.1", "8.8.8.8"], ["127.0.0.1", "169.254.1.1"],
    ["127.0.0.1", "192.168.1.122"], ["127.0.0.1", "127.0.0.1"],
])
def test_unreviewed_or_wrong_san_listener_is_refused(tmp_path, hosts):
    with pytest.raises(ValueError):
        validated_hosts(hosts, _cert(tmp_path))


def test_bind_sockets_releases_first_listener_when_second_fails():
    first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    first.bind(("127.0.0.1", 0))
    port = first.getsockname()[1]
    first.close()
    occupied = bind_sockets(("127.0.0.1",), port)[0]
    try:
        with pytest.raises(OSError):
            bind_sockets(("127.0.0.1", "127.0.0.1"), port)
    finally:
        occupied.close()


def test_one_tls_process_serves_two_explicit_addresses(tmp_path):
    import httpx
    import uvicorn

    material = generate_local_tls(tmp_path / "both", ["127.0.0.2"],
                                  protect=lambda path: path.mkdir(parents=True))
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    sockets = bind_sockets(("127.0.0.1", "127.0.0.2"), port)

    async def app(scope, receive, send):
        assert scope["type"] == "http"
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"one-worker"})

    config = uvicorn.Config(app, ssl_certfile=material["server.pem"],
                            ssl_keyfile=material["server-key.pem"], log_level="critical")
    server = uvicorn.Server(config)
    worker = threading.Thread(target=server.run, kwargs={"sockets": sockets}, daemon=True)
    worker.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.03)
        assert server.started
        context = ssl.create_default_context(cafile=material["ca.pem"])
        with httpx.Client(verify=context, trust_env=False, timeout=3) as client:
            assert client.get(f"https://127.0.0.1:{port}/").text == "one-worker"
            assert client.get(f"https://127.0.0.2:{port}/").text == "one-worker"
    finally:
        server.should_exit = True
        worker.join(timeout=5)
        for listener in sockets:
            listener.close()
    assert not worker.is_alive()
