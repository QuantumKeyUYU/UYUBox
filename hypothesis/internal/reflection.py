"""Reflection helpers used by the pytest plugin."""


def get_pretty_function_description(fn):
    return getattr(fn, "__name__", str(fn))


def is_hypothesis_test(obj):
    return getattr(obj, "is_hypothesis_test", False)
