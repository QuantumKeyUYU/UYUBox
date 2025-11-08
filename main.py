from __future__ import annotations

import sys
import traceback


# ---------- БАЗОВЫЙ ЛОГ В ANDROID LOGCAT ----------

def android_log(message: str) -> None:
    """Пишем диагностику в logcat (и в stderr на всякий случай)."""
    try:
        from jnius import autoclass

        Log = autoclass("android.util.Log")
        Log.e("UYUBox", message)
    except Exception:
        pass
    try:
        print(message, file=sys.stderr)
    except Exception:
        pass


# ---------- ПЫТАЕМСЯ АККУРАТНО ИМПОРТИРОВАТЬ ВСЁ ПРОЧЕЕ ----------

# Если что-то не импортируется (из-за Android-окружения),
# подставляем мягкие заглушки, чтобы не крашиться.

# Значения по умолчанию (заглушки)
def _noop(*_a, **_kw):
    return None


class _DummySessionManager:
    def activate(self):  # type: ignore[override]
        android_log("DummySessionManager.activate() called")

    def remaining_ttl(self) -> int:
        return 60

    def require_active(self):
        return None

    def invalidate(self, reason: str) -> None:
        android_log(f"DummySessionManager.invalidate: {reason}")

    def clear(self) -> None:
        android_log("DummySessionManager.clear()")


class _DummyWatchdog:
    def __init__(self, *_, **__):
        pass

    def start(self):
        android_log("Dummy EnvironmentWatchdog.start()")

    def stop(self):
        android_log("Dummy EnvironmentWatchdog.stop()")


# Подготовим имена, чтобы mypy не ругался
record_event = _noop
entropy_bits = lambda _p: 64  # type: ignore
IntegrityError = Exception
verify_container = lambda _p: {}  # type: ignore
apply_secure_window = lambda *_a, **_kw: None  # type: ignore
enforce_pause_lock = lambda *_a, **_kw: None  # type: ignore
authenticate = lambda *_a, **_kw: None  # type: ignore

SecureFileController = None            # type: ignore
SessionError = Exception
session_manager = _DummySessionManager()
collect_issues = lambda *validators: [  # type: ignore
    issue for sub in validators for issue in (sub or [])
]
validate_file_path = lambda path, must_exist=True: []  # type: ignore
validate_password = lambda password: []  # type: ignore

class SecurityIssue:  # минимальный вариант
    def __init__(self, message: str, severity: str = "info"):
        self.message = message
        self.severity = severity


run_environment_checks = lambda: []  # type: ignore

WizardController = None              # type: ignore
WizardStep = None                    # type: ignore

Recipe = None                        # type: ignore
Step = None                          # type: ignore

class _DummyRegistry:
    def register(self, *_a, **_kw):
        android_log("Dummy registry.register()")

registry = _DummyRegistry()

EnvironmentWatchdog = _DummyWatchdog  # type: ignore


# Теперь пробуем реальные импорты
try:
    from audit.logger import record_event as _real_record_event  # type: ignore

    record_event = _real_record_event
except Exception as exc:
    android_log(f"IMPORT ERROR audit.logger: {exc}")

try:
    from crypto_core.profiles import entropy_bits as _real_entropy_bits  # type: ignore

    entropy_bits = _real_entropy_bits
except Exception as exc:
    android_log(f"IMPORT ERROR crypto_core.profiles: {exc}")

try:
    from integrity.validator import IntegrityError as _RealIntegrityError, verify_container as _real_verify_container  # type: ignore

    IntegrityError = _RealIntegrityError
    verify_container = _real_verify_container
except Exception as exc:
    android_log(f"IMPORT ERROR integrity.validator: {exc}")

try:
    from security.android_security import apply_secure_window as _real_apply_secure_window, enforce_pause_lock as _real_enforce_pause_lock  # type: ignore

    apply_secure_window = _real_apply_secure_window
    enforce_pause_lock = _real_enforce_pause_lock
except Exception as exc:
    android_log(f"IMPORT ERROR security.android_security: {exc}")

try:
    from security.biometric import authenticate as _real_authenticate  # type: ignore

    authenticate = _real_authenticate
except Exception as exc:
    android_log(f"IMPORT ERROR security.biometric: {exc}")

try:
    from security.controller import SecureFileController as _RealSecureFileController  # type: ignore

    SecureFileController = _RealSecureFileController
except Exception as exc:
    android_log(f"IMPORT ERROR security.controller: {exc}")

try:
    from security.session import SessionError as _RealSessionError, session_manager as _real_session_manager  # type: ignore

    SessionError = _RealSessionError
    session_manager = _real_session_manager
except Exception as exc:
    android_log(f"IMPORT ERROR security.session: {exc}")

try:
    from security.validation import (  # type: ignore
        collect_issues as _real_collect_issues,
        validate_file_path as _real_validate_file_path,
        validate_password as _real_validate_password,
    )

    collect_issues = _real_collect_issues
    validate_file_path = _real_validate_file_path
    validate_password = _real_validate_password
except Exception as exc:
    android_log(f"IMPORT ERROR security.validation: {exc}")

try:
    from security.runtime_checks import (  # type: ignore
        SecurityIssue as _RealSecurityIssue,
        run_environment_checks as _real_run_environment_checks,
    )

    SecurityIssue = _RealSecurityIssue
    run_environment_checks = _real_run_environment_checks
except Exception as exc:
    android_log(f"IMPORT ERROR security.runtime_checks: {exc}")

try:
    from ui.wizard import WizardController as _RealWizardController, WizardStep as _RealWizardStep  # type: ignore

    WizardController = _RealWizardController
    WizardStep = _RealWizardStep
except Exception as exc:
    android_log(f"IMPORT ERROR ui.wizard: {exc}")

try:
    from workflow.recipes import Recipe as _RealRecipe, Step as _RealStep, registry as _real_registry  # type: ignore

    Recipe = _RealRecipe
    Step = _RealStep
    registry = _real_registry
except Exception as exc:
    android_log(f"IMPORT ERROR workflow.recipes: {exc}")

try:
    from security.watchdog import EnvironmentWatchdog as _RealEnvironmentWatchdog  # type: ignore

    EnvironmentWatchdog = _RealEnvironmentWatchdog
except Exception as exc:
    android_log(f"IMPORT ERROR security.watchdog: {exc}")


# ---------- KIVY / KIVYMD И UI ----------

from kivy.clock import Clock
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty, StringProperty
from kivy.uix.screenmanager import Screen
from kivymd.app import MDApp
from kivymd.uix.button import MDFlatButton, MDRaisedButton
from kivymd.uix.dialog import MDDialog
from kivymd.uix.label import MDLabel
from kivymd.uix.progressbar import MDProgressBar


KV = """
ScreenManager:
    LockScreen:
    MainScreen:

<LockScreen>:
    name: "lock"
    MDFloatLayout:
        MDLabel:
            text: "Zilant Prime Mobile"
            halign: "center"
            pos_hint: {"center_x": .5, "center_y": .7}
            font_style: "H4"
        MDRaisedButton:
            text: "Разблокировать"
            pos_hint: {"center_x": .5, "center_y": .45}
            on_release: root.unlock()
            disabled: root.lockdown
        MDFlatButton:
            text: "Биометрия"
            pos_hint: {"center_x": .5, "center_y": .35}
            on_release: root.request_biometrics()
            disabled: root.lockdown
        MDLabel:
            text: root.warning_text
            halign: "center"
            theme_text_color: "Error"
            size_hint_y: None
            text_size: self.width, None
            height: self.texture_size[1] if self.texture_size[1] else 0

<MainScreen>:
    name: "main"
    padding: dp(16)
    MDBoxLayout:
        id: container
        orientation: "vertical"
        spacing: dp(12)
        MDTextField:
            id: file_path
            hint_text: "Путь к файлу"
        MDTextField:
            id: output_path
            hint_text: "Выходной файл"
        MDTextField:
            id: password
            hint_text: "Пароль"
            password: True
        MDTextField:
            id: decoy
            hint_text: "Decoy-сообщение (опционально)"
        MDProgressBar:
            id: progress
            value: 0
            max: 1
        MDBoxLayout:
            size_hint_y: None
            height: dp(48)
            spacing: dp(12)
            MDRaisedButton:
                text: "Упаковать"
                on_release: root.start_pack()
            MDRaisedButton:
                text: "Распаковать"
                on_release: root.start_unpack()
            MDFlatButton:
                text: "Метаданные"
                on_release: root.show_metadata()
        MDFlatButton:
            text: "Отмена операции"
            on_release: root.cancel_operation()
        MDLabel:
            id: status
            text: "Готово"
            halign: "left"
        MDLabel:
            id: ttl_status
            text: "Сессия: —"
            halign: "left"
            theme_text_color: "Secondary"
"""


class LockScreen(Screen):
    _dialog: MDDialog | None = None
    lockdown = BooleanProperty(False)
    warning_text = StringProperty("")

    def unlock(self) -> None:
        if self.lockdown:
            self._show_lockdown_dialog()
            return
        session_manager.activate()
        record_event("ui.unlock", details={"method": "passcode"})
        self.manager.current = "main"

    def request_biometrics(self) -> None:
        if self.lockdown:
            self._show_lockdown_dialog()
            return

        def _success() -> None:
            session_manager.activate()
            record_event("ui.unlock", details={"method": "biometric"})
            Clock.schedule_once(
                lambda *_: setattr(self.manager, "current", "main")
            )

        def _failure(reason: str) -> None:
            button = MDFlatButton(text="OK")
            dialog = MDDialog(title="Биометрия", text=reason, buttons=[button])
            button.bind(on_release=lambda *_: dialog.dismiss())
            dialog.open()

        try:
            authenticate(
                "Подтвердите личность",
                on_success=_success,
                on_failure=_failure,
            )
        except Exception as exc:
            android_log(f"authenticate() failed: {exc}")
            _failure("Биометрия недоступна на этом устройстве.")

    def report_issues(self, issues: list[SecurityIssue]) -> None:
        if not issues:
            return
        messages = [f"• {issue.message}" for issue in issues]
        self.warning_text = "\n".join(messages)
        if any(getattr(issue, "severity", "") == "critical" for issue in issues):
            self.lockdown = True
            session_manager.invalidate("Обнаружены критические проблемы среды")

    def _show_lockdown_dialog(self) -> None:
        if self._dialog:
            return
        button = MDFlatButton(text="OK")
        dialog = MDDialog(
            title="Защита активна",
            text="Обнаружена небезопасная среда. Устраните угрозы перед использованием.",
            buttons=[button],
        )
        button.bind(on_release=lambda *_: dialog.dismiss())
        dialog.bind(on_dismiss=lambda *_: setattr(self, "_dialog", None))
        self._dialog = dialog
        dialog.open()


class MainScreen(Screen):
    busy = BooleanProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.progress_bar: MDProgressBar | None = None
        self.status_label: MDLabel | None = None
        self.ttl_label: MDLabel | None = None
        self.controller = SecureFileController() if SecureFileController else None
        self._wizard: WizardController | None = None
        self._ttl_event = None

    def on_kv_post(self, base_widget):
        self.progress_bar = self.ids.progress
        self.status_label = self.ids.status
        self.ttl_label = self.ids.ttl_status
        self._update_session_ttl()
        if self._ttl_event is None:
            self._ttl_event = Clock.schedule_interval(
                self._update_session_ttl, 1.0
            )

    def _set_status(self, text: str) -> None:
        if self.status_label:
            self.status_label.text = text

    def _set_progress(self, value: float) -> None:
        if self.progress_bar:
            self.progress_bar.value = value

    def _update_session_ttl(self, *_args) -> None:
        ttl = 0
        try:
            ttl = int(session_manager.remaining_ttl())
        except Exception:
            ttl = 0
        if self.ttl_label:
            if ttl <= 0:
                self.ttl_label.text = "Сессия: заблокирована"
            else:
                self.ttl_label.text = f"Сессия: {ttl}с"

    def _show_dialog(self, title: str, text: str) -> None:
        button = MDFlatButton(text="OK")
        dialog = MDDialog(title=title, text=text, buttons=[button])
        button.bind(on_release=lambda *_: dialog.dismiss())
        dialog.open()

    def _run_wizard(self, *, on_finish) -> None:
        # если нет реального WizardController — просто сразу вызываем on_finish
        if WizardController is None or WizardStep is None:
            on_finish()
            return

        password = self.ids.password.text

        def _enter_validation() -> None:
            self._set_status("Валидация параметров...")

        def _complete_validation() -> None:
            self._set_status("Параметры подтверждены")

        def _enter_entropy() -> None:
            self._set_status("Оценка энтропии пароля...")
            try:
                bits = int(entropy_bits(password))
                self._show_dialog("Энтропия", f"Оценка энтропии: {bits} бит")
            except Exception as exc:
                android_log(f"entropy_bits() failed: {exc}")

        steps = [
            WizardStep(
                title="validation",
                on_enter=_enter_validation,
                on_complete=_complete_validation,
            ),
            WizardStep(
                title="entropy",
                on_enter=_enter_entropy,
                on_complete=lambda: None,
            ),
        ]

        def _wrapped_finish() -> None:
            try:
                on_finish()
            finally:
                self._wizard = None

        self._wizard = WizardController(steps=steps, on_finish=_wrapped_finish)
        self._wizard.start()
        wizard_ref = self._wizard
        for index in range(len(steps)):
            Clock.schedule_once(
                lambda *_: wizard_ref.complete_current(), (index + 1) * 0.05
            )

    def cancel_operation(self) -> None:
        if self.controller:
            self.controller.cancel()
        self._set_status("Операция отменена")
        self._set_progress(0)
        self.busy = False

    def _validate_common(self) -> tuple[str, str, str | None]:
        file_path = self.ids.file_path.text
        output_path = self.ids.output_path.text or (file_path + ".zilant")
        password = self.ids.password.text
        decoy_message = self.ids.decoy.text or None
        try:
            session_manager.require_active()
        except SessionError as exc:
            self._show_dialog("Сессия заблокирована", str(exc))
            raise ValueError(str(exc)) from exc
        issues = collect_issues(
            validate_file_path(file_path, must_exist=True),
            validate_password(password),
        )
        if issues:
            text = "\n".join(f"{issue.field}: {issue.message}" for issue in issues)
            self._show_dialog("Ошибки", text)
            raise ValueError(text)
        return file_path, output_path, decoy_message

    def start_pack(self) -> None:
        if not self.controller:
            self._show_dialog(
                "Недоступно",
                "Контроллер шифрования недоступен в этой сборке.",
            )
            return
        try:
            file_path, output_path, decoy_message = self._validate_common()
        except ValueError:
            return

        def _finish_wizard() -> None:
            self._set_status("Запуск упаковки...")
            self._set_progress(0)
            self.busy = True
            self.controller.pack(
                file_path,
                output_path,
                self.ids.password.text,
                decoy_message=decoy_message,
                progress_cb=lambda value: Clock.schedule_once(
                    lambda *_: self._set_progress(value)
                ),
                completion_cb=self._on_operation_complete,
            )

        self._run_wizard(on_finish=_finish_wizard)

    def start_unpack(self) -> None:
        if not self.controller:
            self._show_dialog(
                "Недоступно",
                "Контроллер шифрования недоступен в этой сборке.",
            )
            return
        try:
            file_path, output_path, _ = self._validate_common()
        except ValueError:
            return

        def _finish_wizard() -> None:
            self._set_status("Запуск распаковки...")
            self._set_progress(0)
            self.busy = True
            self.controller.unpack(
                file_path,
                output_path,
                self.ids.password.text,
                progress_cb=lambda value: Clock.schedule_once(
                    lambda *_: self._set_progress(value)
                ),
                completion_cb=self._on_operation_complete,
            )

        self._run_wizard(on_finish=_finish_wizard)

    def _on_operation_complete(self, error: str | None) -> None:
        def _update(*_args):
            self.busy = False
            if error:
                self._set_status(f"Ошибка: {error}")
                self._show_dialog("Ошибка", error)
            else:
                self._set_status("Операция завершена")
                record_event("ui.operation.complete", details={"screen": "main"})
                self._show_dialog("Успех", "Операция завершена")
            self._set_progress(0)

        Clock.schedule_once(_update)

    def show_metadata(self) -> None:
        try:
            file_path = self.ids.file_path.text
            if not file_path:
                raise ValueError("Укажите путь к контейнеру.")
            metadata = verify_container(file_path)
            text = "\n".join(f"{key}: {value}" for key, value in metadata.items())
            self._show_dialog("Метаданные", text)
        except (IntegrityError, ValueError) as exc:
            self._show_dialog("Ошибка метаданных", str(exc))
        except Exception as exc:
            android_log(f"verify_container() failed: {exc}")
            self._show_dialog("Ошибка", "Не удалось прочитать метаданные.")


class ZilantPrimeApp(MDApp):
    watchdog: EnvironmentWatchdog | None = None

    def build(self):
        try:
            self.title = "Zilant Prime Mobile"
            Window.size = (420, 760)
            try:
                apply_secure_window(Window)
                enforce_pause_lock(self)
            except Exception as exc:
                android_log(f"secure_window / pause_lock failed: {exc}")

            self._register_recipes()

            try:
                issues = run_environment_checks()
            except Exception as exc:
                android_log(f"run_environment_checks() failed: {exc}")
                issues = []

            sm = Builder.load_string(KV)

            if issues:
                record_event(
                    "security.environment",
                    details={
                        "issues": [
                            {
                                "severity": getattr(issue, "severity", ""),
                                "message": issue.message,
                            }
                            for issue in issues
                        ]
                    },
                )
                lock_screen: LockScreen = sm.get_screen("lock")
                lock_screen.report_issues(issues)
                if any(
                    getattr(issue, "severity", "") == "critical"
                    for issue in issues
                ):
                    session_manager.invalidate(
                        "Обнаружены угрозы среды при запуске"
                    )

            lock_screen = sm.get_screen("lock")
            main_screen: MainScreen = sm.get_screen("main")

            def _lockdown_handler(found_issues: list[SecurityIssue]) -> None:
                session_manager.invalidate("Watchdog заблокировал сессию")
                if main_screen.controller:
                    main_screen.controller.cancel()
                main_screen.busy = False
                main_screen._set_status(
                    "Среда небезопасна. Сессия заблокирована."
                )
                sm.current = "lock"
                lock_screen.lockdown = True
                lock_screen.report_issues(found_issues)

            try:
                self.watchdog = EnvironmentWatchdog(
                    interval=10.0,
                    scheduler=lambda fn: Clock.schedule_once(
                        lambda *_: fn()
                    ),
                    issue_handler=lock_screen.report_issues,
                    lockdown_handler=_lockdown_handler,
                )
                self.watchdog.start()
            except Exception as exc:
                android_log(f"EnvironmentWatchdog init/start failed: {exc}")
                self.watchdog = None

            return sm

        except Exception:
            tb = traceback.format_exc()
            android_log("FATAL in build():\n" + tb)
            # минимальный fallback-экран, чтобы приложение не закрывалось сразу
            from kivymd.uix.label import MDLabel
            from kivymd.uix.boxlayout import MDBoxLayout

            layout = MDBoxLayout(orientation="vertical", padding=dp(16))
            layout.add_widget(
                MDLabel(
                    text="Ошибка инициализации приложения.\n"
                    "Смотрите лог (logcat) для деталей.",
                    halign="center",
                )
            )
            return layout

    def _register_recipes(self) -> None:
        if Recipe is None or Step is None:
            return
        try:
            registry.register(
                Recipe(
                    name="default_pack",
                    steps=[
                        Step(
                            name="audit.start",
                            action=lambda: record_event(
                                "recipe.audit", details={"mode": "start"}
                            ),
                        ),
                        Step(
                            name="audit.finish",
                            action=lambda: record_event(
                                "recipe.audit", details={"mode": "finish"}
                            ),
                        ),
                    ],
                )
            )
        except Exception as exc:
            android_log(f"registry.register() failed: {exc}")

    def on_stop(self) -> None:
        try:
            if self.watchdog:
                self.watchdog.stop()
        except Exception as exc:
            android_log(f"watchdog.stop() failed: {exc}")
        try:
            session_manager.clear()
        except Exception as exc:
            android_log(f"session_manager.clear() failed: {exc}")


if __name__ == "__main__":
    try:
        try:
            from android.permissions import (
                Permission,
                request_permissions,
            )

            request_permissions(
                [
                    Permission.READ_EXTERNAL_STORAGE,
                    Permission.WRITE_EXTERNAL_STORAGE,
                ]
            )
        except Exception as exc:
            android_log(f"permissions request failed: {exc}")

        ZilantPrimeApp().run()

    except Exception:
        tb = traceback.format_exc()
        android_log("TOP-LEVEL CRASH:\n" + tb)
