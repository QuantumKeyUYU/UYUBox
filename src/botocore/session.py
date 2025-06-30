# mypy: ignore-errors
"""
Простейшая сессия + клиент, которого хватает для Stubber’а.
"""


class _Body:
    def read(self) -> bytes:  # имитируем s3 get_object()['Body'].read()
        return b""


class _DummyClient:
    def put_object(self, **kw):  # noqa: D401
        return {"ETag": "deadbeef"}

    def get_object(self, **kw):  # noqa: D401
        return {"Body": _Body()}


class Session:  # noqa: D401
    def create_client(self, service_name, *args, **kwargs):
        return _DummyClient()


def get_session() -> Session:  # noqa: D401
    return Session()
