from __future__ import annotations


class exceptions:
    class SSLError(Exception):
        pass

    class RequestException(Exception):
        pass


class Response:
    def __init__(self, data: dict | None = None, status_code: int = 200) -> None:
        self._data = data or {}
        self.status_code = status_code

    def json(self) -> dict:
        return self._data


class Session:
    def __init__(self) -> None:
        pass

    def get(self, url: str, *args, **kwargs):
        return post(url, *args, **kwargs)

    def post(self, url: str, *args, **kwargs):
        return post(url, *args, **kwargs)


def post(url: str, *args, **kwargs) -> Response:
    return Response()
