import importlib
import os

def reload_watchdog(tmp_path):
    os.environ["ZILANT_AUDIT_DIR"] = str(tmp_path)
    import audit.logger as audit_logger

    importlib.reload(audit_logger)
    import security.watchdog as watchdog_module

    return importlib.reload(watchdog_module)


def test_watchdog_triggers_lockdown(tmp_path):
    watchdog_module = reload_watchdog(tmp_path)
    issues = []

    def check_fn():
        return issues

    dispatched = []
    locked = []

    def issue_handler(found):
        dispatched.append(found)

    def lockdown_handler(found):
        locked.append(found)

    watchdog = watchdog_module.EnvironmentWatchdog(
        interval=0.1,
        scheduler=lambda fn: fn(),
        check_fn=check_fn,
        issue_handler=issue_handler,
        lockdown_handler=lockdown_handler,
    )

    # No issues - nothing happens.
    watchdog.run_once()
    assert not dispatched

    from security.runtime_checks import SecurityIssue

    issue = SecurityIssue(severity="critical", message="frida")
    issues.append(issue)

    watchdog.run_once()

    assert dispatched
    assert dispatched[0][0].message == "frida"
    assert locked

    # Re-running with the same fingerprint should not duplicate notifications.
    watchdog.run_once()
    assert len(dispatched) == 1

    # Clearing issues resets the fingerprint allowing future notifications.
    issues.clear()
    watchdog.run_once()
    issues.append(SecurityIssue(severity="critical", message="root"))
    watchdog.run_once()
    assert len(dispatched) == 2
