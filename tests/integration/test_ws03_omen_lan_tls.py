"""Bind a harmless ASGI response on Omen loopback and its current Wi-Fi IP."""
import os
import socket
import ssl
import threading
import time

import httpx
import pytest
import uvicorn

from backend.application.ops.listeners import bind_sockets, validated_hosts
from backend.cli import generate_local_tls


def test_ephemeral_private_lan_and_loopback_have_exact_tls_identity(tmp_path):
    lan = os.environ.get("RAVENX_TEST_PRIVATE_IPV4", "192.168.1.121")
    validated_hosts(["127.0.0.1", lan], None)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as interface:
        try:
            interface.bind((lan, 0))
        except OSError:
            if "RAVENX_TEST_PRIVATE_IPV4" in os.environ:
                raise
            pytest.skip("the recorded Omen pilot address is not assigned")
    material = generate_local_tls(tmp_path / "tls", [lan],
                                  protect=lambda path: path.mkdir(parents=True))
    other_ca = generate_local_tls(tmp_path / "other", [lan],
                                  protect=lambda path: path.mkdir(parents=True))["ca.pem"]
    assert validated_hosts(["127.0.0.1", lan], material["server.pem"])
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    listeners = bind_sockets(("127.0.0.1", lan), port)

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ws03-probe"})

    server = uvicorn.Server(uvicorn.Config(
        app, ssl_certfile=material["server.pem"], ssl_keyfile=material["server-key.pem"],
        log_level="critical"))
    worker = threading.Thread(target=server.run, kwargs={"sockets": listeners}, daemon=True)
    worker.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.03)
        assert server.started
        trusted = ssl.create_default_context(cafile=material["ca.pem"])
        with httpx.Client(verify=trusted, trust_env=False, timeout=3) as client:
            assert client.get(f"https://127.0.0.1:{port}/ready").text == "ws03-probe"
            assert client.get(f"https://{lan}:{port}/ready").text == "ws03-probe"
        untrusted = ssl.create_default_context(cafile=other_ca)
        with httpx.Client(verify=untrusted, trust_env=False, timeout=3) as client:
            with pytest.raises(httpx.ConnectError):
                client.get(f"https://{lan}:{port}/ready")
    finally:
        server.should_exit = True
        worker.join(timeout=5)
        for listener in listeners:
            listener.close()
    assert not worker.is_alive()
