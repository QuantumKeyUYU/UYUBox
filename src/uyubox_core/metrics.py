# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from __future__ import annotations

from contextlib import contextmanager
from functools import wraps
from prometheus_client import Counter, Gauge, Histogram, generate_latest
from typing import Any, Callable, Iterator, cast

__all__ = ["metrics", "Metrics"]


class Metrics:
    def __init__(self) -> None:
        self.requests_total: Counter = Counter("requests_total", "Total processed requests", ["name"])
        self.request_duration_seconds: Histogram = Histogram(
            "request_duration_seconds",
            "Request duration in seconds",
            ["name"],
        )
        self.command_duration_seconds: Histogram = Histogram(
            "command_duration_seconds",
            "CLI command duration in seconds",
            ["name"],
            buckets=[0.1, 0.5, 1, 5, 10],
        )
        self.files_processed_total: Counter = Counter(
            "files_processed_total",
            "Number of files processed",
        )
        self.encryption_duration_seconds: Histogram = Histogram(
            "encryption_duration_seconds",
            "Time spent encrypting/decrypting",
        )
        self.inflight_requests: Gauge = Gauge("inflight_requests", "In-flight requests", ["name"])

    @contextmanager
    def track(self, name: str) -> Iterator[None]:
        self.inflight_requests.labels(name).inc()
        with self.request_duration_seconds.labels(name).time():
            yield
        self.inflight_requests.labels(name).dec()
        self.requests_total.labels(name).inc()

    def record_cli(self, name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator to time CLI command execution."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                with self.command_duration_seconds.labels(name).time():
                    return func(*args, **kwargs)

            return wrapper

        return decorator

    def export(self) -> bytes:
        return cast(bytes, generate_latest())


metrics = Metrics()
