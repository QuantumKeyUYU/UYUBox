# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from zilant_prime_core import health


def test_health_endpoints(monkeypatch):
    monkeypatch.setattr(health.time, "sleep", lambda n: None)
    with health.app.test_client() as c:
        assert c.get("/healthz").data == b"ok"
        metrics_resp = c.get("/metrics")
        assert metrics_resp.status_code == 200
        assert b"files_processed_total" in metrics_resp.data
        assert c.get("/pprof?duration=0").status_code == 200


def test_start_server(monkeypatch):
    called = {}

    def fake_run(port, **kwargs):
        called["port"] = port

    monkeypatch.setattr(health.app, "run", fake_run)
    th = health.start_server(1234)
    th.join(0.01)
    assert called["port"] == 1234
