"""Helpers for applying deep on-device protections on Android."""
from __future__ import annotations

import logging
from typing import Optional

_logger = logging.getLogger(__name__)


def apply_secure_window(window: Optional[object]) -> None:
    """Enable FLAG_SECURE and other runtime defences on Android builds.

    The code gracefully degrades when running on desktop where pyjnius is not
    available. When we are on Android, the method prevents screenshots and
    activates secure window flags to make shoulder surfing harder.
    """

    if window is None:
        return
    try:
        # Late import to avoid failing during desktop testing.
        from jnius import autoclass

        activity = autoclass("org.kivy.android.PythonActivity").mActivity
        window_obj = activity.getWindow()
        LayoutParams = autoclass("android.view.WindowManager$LayoutParams")
        window_obj.addFlags(LayoutParams.FLAG_SECURE)
        window_obj.addFlags(LayoutParams.FLAG_KEEP_SCREEN_ON)
        _logger.info("Applied Android secure window policies")
    except Exception as exc:  # pragma: no cover - environment dependent
        _logger.debug("Could not apply Android secure flags: %s", exc)


def enforce_pause_lock(app: object) -> None:
    """Force app relock on pause/resume to protect against task switch leaks."""

    if app is None:
        return

    def _on_pause(*_args, **_kwargs):
        app.root.current = "lock"
        return True

    def _on_resume(*_args, **_kwargs):
        app.root.current = "lock"
        return True

    if hasattr(app, "on_pause"):
        app.on_pause = _on_pause  # type: ignore[assignment]
    if hasattr(app, "on_resume"):
        app.on_resume = _on_resume  # type: ignore[assignment]


class KeyStoreUnavailable(RuntimeError):
    """Raised when the Android KeyStore could not be accessed."""


def fetch_keystore_secret(alias: str) -> bytes:
    """Retrieve a binary secret from the Android KeyStore.

    Falls back to returning an empty bytes object if the KeyStore cannot be
    used. The calling code must combine the returned secret with a password to
    obtain the full key (split secret approach).
    """

    try:
        from jnius import autoclass

        KeyStore = autoclass("java.security.KeyStore")
        key_store = KeyStore.getInstance("AndroidKeyStore")
        key_store.load(None)
        entry = key_store.getEntry(alias, None)
        if entry is None:
            raise KeyStoreUnavailable(f"alias {alias!r} missing")
        secret_key = entry.getSecretKey()
        return bytes(secret_key.getEncoded())
    except Exception as exc:  # pragma: no cover - environment dependent
        _logger.debug("Keystore unavailable: %s", exc)
        return b""
