from __future__ import annotations

from . import strategies as strategies
import inspect
import functools

__version__ = "6.100.0"


class HealthCheck:
    function_scoped_fixture = object()


def settings(**_kwargs):  # pragma: no cover - simplified
    def decorator(fn):
        return fn

    return decorator


def given(**kwargs):
    def decorator(fn):
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapper(*args, **fkwargs):
            for name, strat in kwargs.items():
                fkwargs[name] = strat() if callable(strat) else strat
            return fn(*args, **fkwargs)

        wrapper.hypothesis_inner_test = fn
        wrapper.is_hypothesis_test = True
        wrapper.__signature__ = sig.replace(parameters=[p for p in sig.parameters.values() if p.name not in kwargs])
        return wrapper

    return decorator


def is_hypothesis_test(obj) -> bool:  # pragma: no cover - minimal stub
    return getattr(obj, "is_hypothesis_test", False)
