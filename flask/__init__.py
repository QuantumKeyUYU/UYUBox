from __future__ import annotations


class Response:
    def __init__(self, data: str | bytes = "", mimetype: str = "text/plain", status: int = 200) -> None:
        self.data = data.encode() if isinstance(data, str) else data
        self.mimetype = mimetype
        self.status_code = status


class Flask:
    def __init__(self, name: str) -> None:
        self.name = name
        self._routes: dict[str, callable] = {}

    def route(self, path: str):
        def decorator(func):
            self._routes[path] = func
            return func

        return decorator

    def test_client(self):
        app = self

        class Client:
            def get(self, path: str):
                func = app._routes[path.split("?")[0]]
                return func()

        return Client()

    def run(self, port: int = 5000, use_reloader: bool = False) -> None:  # noqa: D401
        pass
