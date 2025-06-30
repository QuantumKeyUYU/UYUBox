# mypy: ignore-errors
"""
Лёгкая «заглушка» для пакета *botocore*, чтоб юнит-тесты,
ожидающие boto3/botocore, работали без тяжёлых зависимостей AWS.

Реализовано:
    • botocore.get_session()
    • botocore.session.Session
    • botocore.stub.Stubber
    • boto3.client(...)
Никаких реальных сетевых вызовов не совершается.
"""

import sys
from types import ModuleType

from . import session as _session
from . import stub as stub  # re-export для «from botocore.stub import Stubber»

__all__ = ["get_session", "stub", "_session"]


# --------------------------------------------------------------------- #
# public helpers
# --------------------------------------------------------------------- #
def get_session() -> "_session.Session":  # noqa: D401 – простая обёртка
    """Имитация `botocore.session.get_session()`."""
    return _session.Session()


# --------------------------------------------------------------------- #
# регистрируем суб-модули в sys.modules
# --------------------------------------------------------------------- #
# чтобы `import botocore.session` / `botocore.stub` не падали
sys.modules.setdefault(__name__ + ".session", _session)
sys.modules.setdefault(__name__ + ".stub", stub)

# лёгкая заглушка под `boto3`
_boto3 = ModuleType("boto3")
_boto3.client = lambda *a, **kw: _session.Session().create_client(*a, **kw)  # type: ignore[arg-type]
sys.modules.setdefault("boto3", _boto3)
