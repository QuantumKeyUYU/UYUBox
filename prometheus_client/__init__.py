class _Value:
    def __init__(self):
        self._v = 0.0

    def inc(self, amount=1):
        self._v += amount

    def dec(self, amount=1):
        self._v -= amount

    def get(self):
        return self._v


class _Timer:
    def __init__(self, metric):
        self.metric = metric

    def __enter__(self):
        return None

    def __exit__(self, exc_type, exc, tb):
        self.metric.observe(0.0)


class _Metric:
    def __init__(self, *args, **kwargs):
        self._value = _Value()

    def labels(self, *labels):
        return self

    def inc(self, amount=1):
        self._value.inc(amount)

    def dec(self, amount=1):
        self._value.dec(amount)

    def set(self, value):
        self._value._v = value

    def observe(self, value):
        self._value._v = value

    def time(self):
        return _Timer(self)

    def collect(self):
        Sample = type("Sample", (), {"name": "dummy_count", "value": float(self._value.get())})
        Holder = type("Holder", (), {"samples": [Sample]})
        return [Holder]


Counter = Gauge = Histogram = _Metric


def generate_latest():
    names = [
        "requests_total",
        "files_processed_total",
        "command_duration_seconds_bucket",
    ]
    return ("\n".join(names) + "\n").encode()
