from zilant_prime_core.health import app


def test_health_endpoints():
    client = app.test_client()
    assert client.get("/healthz").status_code == 200
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert b"files_processed_total" in resp.data
