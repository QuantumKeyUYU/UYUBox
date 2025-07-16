from __future__ import annotations


class exceptions:
    class SSLError(Exception):
        pass


def post(url: str, *args, **kwargs):
    class Resp:
        status_code = 200

        def json(self):
            return {}

    return Resp()
