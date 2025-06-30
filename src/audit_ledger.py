from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Final

__all__ = [
    "record_action",
    "record_decoy_event",
    "record_decoy_purged",
    "record_decoy_removed_early",
    "record_self_heal_triggered",
    "record_self_heal_done",
]

_LEDGER: Final[Path] = Path("audit-ledger.jsonl")
_logger = logging.getLogger("audit")


def _append(entry: dict[str, Any]) -> None:
    """Записать JSON-строку, добавить SHA-256, вывести читабельный лог."""
    # Чистый сериализуемый объект без sha256:
    ser = json.dumps(
        {k: entry[k] for k in ("timestamp", "action", "params")},
        sort_keys=True,
        separators=(",", ":"),
    )
    entry["sha256"] = hashlib.sha256(ser.encode()).hexdigest()

    with _LEDGER.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, separators=(",", ":")) + "\n")

    act = entry["action"]
    prm = entry["params"]
    if act in {"decoy_purged", "decoy_removed_early"} and "file" in prm:
        # строка нужна ровно в таком формате для тестов
        _logger.info("%s: %s", act.replace("_", " "), prm["file"])
    else:
        _logger.info("%s: %s", act, prm)


def record_action(action: str, params: dict[str, Any]) -> None:
    _append({"timestamp": int(time.time()), "action": action, "params": params})


# ----------------------------------------------------------------- shortcuts
def record_decoy_event(params: dict[str, Any]) -> None:  # для CLI-кода
    record_action("decoy_event", params)


def record_decoy_purged(path: str) -> None:
    record_action("decoy_purged", {"file": path})


def record_decoy_removed_early(path: str) -> None:
    record_action("decoy_removed_early", {"file": path})


def record_self_heal_triggered(info: dict[str, Any]) -> None:
    record_action("self_heal_triggered", info)


def record_self_heal_done(info: dict[str, Any]) -> None:
    record_action("self_heal_done", info)
