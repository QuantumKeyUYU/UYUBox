from __future__ import annotations


class exceptions:
    class SSLError(Exception):
        pass


class Session:
    def __init__(self) -> None:
        pass

    def get(self, url: str, *args, **kwargs):
        return post(url, *args, **kwargs)

    def post(self, url: str, *args, **kwargs):
        return post(url, *args, **kwargs)


def post(url: str, *args, **kwargs):
    class Resp:
        status_code = 200

        def json(self):
            return {}

    return Resp()
