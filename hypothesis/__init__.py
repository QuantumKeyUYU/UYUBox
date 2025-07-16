from __future__ import annotations

from . import strategies as strategies


class HealthCheck:
    function_scoped_fixture = object()


def settings(**_kwargs):  # pragma: no cover - simplified
    def decorator(fn):
        return fn

    return decorator


def given(**kwargs):
    def decorator(fn):
        def wrapper(*args, **_):
            vals = {k: (v() if callable(v) else v) for k, v in kwargs.items()}
            return fn(*args, **vals)

        return wrapper

    return decorator
