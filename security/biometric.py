"""Biometric unlock helpers with graceful fallback."""
from __future__ import annotations

from typing import Callable

try:  # pragma: no cover - platform specific
    from jnius import autoclass
except Exception:  # pragma: no cover
    autoclass = None  # type: ignore


class BiometricUnavailable(RuntimeError):
    pass


def authenticate(reason: str, *, on_success: Callable[[], None], on_failure: Callable[[str], None]) -> None:
    if not autoclass:
        on_failure("Биометрия недоступна на этой платформе.")
        return
    try:  # pragma: no cover - requires Android runtime
        BiometricPrompt = autoclass("androidx.biometric.BiometricPrompt")
        activity = autoclass("org.kivy.android.PythonActivity").mActivity
        executor = activity.getMainExecutor()

        class Callback(BiometricPrompt.AuthenticationCallback):  # type: ignore[misc]
            def onAuthenticationSucceeded(self, result):  # noqa: N802
                on_success()

            def onAuthenticationError(self, error_code, err_string):  # noqa: N802
                on_failure(str(err_string))

            def onAuthenticationFailed(self):  # noqa: N802
                on_failure("Биометрия отклонена")

        prompt = BiometricPrompt(activity, executor, Callback())
        prompt_info_builder = BiometricPrompt.PromptInfo.Builder()
        prompt_info_builder.setTitle("Zilant Prime Biometric")
        prompt_info_builder.setSubtitle(reason)
        prompt_info_builder.setNegativeButtonText("Использовать пароль")
        prompt.authenticate(prompt_info_builder.build())
    except Exception as exc:
        on_failure(str(exc))
