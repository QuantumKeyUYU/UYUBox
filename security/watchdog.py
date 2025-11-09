"""Background watchdog that keeps monitoring the environment posture."""
from __future__ import annotations

import threading
from typing import Callable, Iterable, Optional

from audit.logger import record_event
from security.runtime_checks import SecurityIssue, run_environment_checks


IssueHandler = Callable[[list[SecurityIssue]], None]
Scheduler = Callable[[Callable[[], None]], None]
CheckFn = Callable[[], Iterable[SecurityIssue]]


class EnvironmentWatchdog:
    """Periodically evaluate environment integrity and trigger lockdowns."""

    def __init__(
        self,
        *,
        interval: float = 15.0,
        scheduler: Scheduler | None = None,
        check_fn: CheckFn | None = None,
        issue_handler: IssueHandler | None = None,
        lockdown_handler: Optional[Callable[[list[SecurityIssue]], None]] = None,
    ) -> None:
        self.interval = interval
        self.scheduler = scheduler or (lambda fn: fn())
        self.check_fn = check_fn or run_environment_checks
        self.issue_handler = issue_handler
        self.lockdown_handler = lockdown_handler
        self._stop_event = threading.Event()
        self._timer: threading.Timer | None = None
        self._last_fingerprint: tuple[tuple[str, str], ...] | None = None

    def start(self) -> None:
        """Start the watchdog loop."""

        self.stop()
        self._stop_event.clear()
        self._evaluate(schedule=True)

    def stop(self) -> None:
        """Stop the watchdog loop."""

        self._stop_event.set()
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def run_once(self) -> None:
        """Execute a single integrity check immediately."""

        self._evaluate(schedule=False)

    def _schedule_next(self) -> None:
        if self._stop_event.is_set():
            return
        timer = threading.Timer(self.interval, self._evaluate)
        timer.daemon = True
        self._timer = timer
        timer.start()

    def _evaluate(self, *, schedule: bool = True) -> None:
        if self._stop_event.is_set():
            return
        issues = list(self.check_fn())
        if issues:
            fingerprint = tuple(sorted((issue.severity, issue.message) for issue in issues))
            if fingerprint != self._last_fingerprint:
                self._last_fingerprint = fingerprint
                self._notify(issues)
        else:
            if self._last_fingerprint is not None:
                self._last_fingerprint = None
                self._notify([])
        if schedule:
            self._schedule_next()

    def _notify(self, issues: list[SecurityIssue]) -> None:
        def _dispatch() -> None:
            if issues:
                record_event(
                    "security.watchdog.issue",
                    details={
                        "issues": [
                            {"severity": issue.severity, "message": issue.message}
                            for issue in issues
                        ]
                    },
                )
                if self.issue_handler:
                    self.issue_handler(issues)
                if any(issue.severity == "critical" for issue in issues):
                    record_event("security.watchdog.lockdown", details={"count": len(issues)})
                    if self.lockdown_handler:
                        self.lockdown_handler(issues)
            else:
                record_event("security.watchdog.clear", details={})
                if self.issue_handler:
                    self.issue_handler([])

        self.scheduler(_dispatch)


__all__ = ["EnvironmentWatchdog"]
