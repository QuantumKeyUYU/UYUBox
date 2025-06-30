# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import time

from zilant_prime_core.metrics import metrics


def test_metrics_track():
    with metrics.track("test"):
        time.sleep(0.01)
    metrics.files_processed_total.inc()
    metrics.encryption_duration_seconds.observe(0.02)
    assert metrics.requests_total.labels("test")._value.get() == 1
    assert metrics.inflight_requests.labels("test")._value.get() == 0
    samples = metrics.request_duration_seconds.collect()[0].samples
    assert any(s.name.endswith("_count") and s.value == 1.0 for s in samples)


def test_metrics_export_returns_bytes():
    out = metrics.export()
    assert isinstance(out, bytes)
    assert b"requests_total" in out
    assert b"files_processed_total" in out
