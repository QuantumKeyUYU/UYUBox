class _Value:
    def __init__(self) -> None:
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
        # Histogram count increments
        self.metric.inc()


class _Metric:
    def __init__(self, name: str, *args, **kwargs) -> None:
        self._name = name
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
        Sample = type(
            "Sample",
            (),
            {"name": f"{self._name}_count", "value": float(self._value.get())},
        )
        Holder = type("Holder", (), {"samples": [Sample]})
        return [Holder]


def Counter(name, *args, **kwargs):
    return _Metric(name)


def Gauge(name, *args, **kwargs):
    return _Metric(name)


def Histogram(name, *args, **kwargs):
    return _Metric(name)


def generate_latest():
    names = [
        "requests_total",
        "files_processed_total",
        "command_duration_seconds_bucket",
    ]
    return ("\n".join(names) + "\n").encode()
