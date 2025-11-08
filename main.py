from __future__ import annotations

from typing import Callable, List, Optional, Tuple

from kivy.clock import Clock
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty, StringProperty
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.utils import platform

from kivymd.app import MDApp
from kivymd.uix.button import MDFlatButton, MDRaisedButton
from kivymd.uix.dialog import MDDialog
from kivymd.uix.label import MDLabel
from kivymd.uix.progressbar import MDProgressBar


# ---------------------------------------------------------------------------
# БЕЗОПАСНЫЕ ИМПОРТЫ С ЗАПАСНЫМИ ВАРИАНТАМИ
# ---------------------------------------------------------------------------

def _log(msg: str) -> None:
    # Пишет в консоль (на Android это улетит в logcat).
    print(f"[ZILANT] {msg}")


try:
    from audit.logger import record_event as _record_event
except Exception:  # pragma: no cover - mobile fallback

    def _record_event(event: str, *, details=None):
        _log(f"audit.logger unavailable, event={event}, details={details}")


try:
    from crypto_core.profiles import entropy_bits as _entropy_bits
except Exception:  # pragma: no cover

    def _entropy_bits(password: str) -> float:
        # Грубая оценка энтропии, если настоящая функция недоступна.
        return max(0.0, len(password) * 2.5)


try:
    from integrity.validator import IntegrityError, verify_container as _verify_container
except Exception:  # pragma: no cover

    class IntegrityError(RuntimeError):
        pass

    def _verify_container(path: str):
        raise IntegrityError("Модуль проверки целостности недоступен на этой платформе.")


try:
    from security.android_security import apply_secure_window, enforce_pause_lock
except Exception:  # pragma: no cover

    def apply_secure_window(_window):
        _log("android_security.apply_secure_window() fallback")

    def enforce_pause_lock(_app):
        _log("android_security.enforce_pause_lock() fallback")


try:
    from security.biometric import authenticate as _authenticate
except Exception:  # pragma: no cover

    def _authenticate(_title: str, on_success: Callable[[], None], on_failure: Callable[[str], None]):
        on_failure("Биометрия недоступна в этой сборке.")


try:
    from security.controller import SecureFileController as _SecureFileController
except Exception:  # pragma: no cover

    class _SecureFileController:
        def cancel(self) -> None:
            _log("SecureFileController.cancel() fallback")

        def pack(self, *_args, **_kwargs) -> None:
            raise RuntimeError("Криптографическое ядро недоступно. Упаковка невозможна.")

        def unpack(self, *_args, **_kwargs) -> None:
            raise RuntimeError("Криптографическое ядро недоступно. Распаковка невозможна.")


try:
    from security.session import SessionError, session_manager
except Exception:  # pragma: no cover

    class SessionError(RuntimeError):
        pass

    class _DummySessionManager:
        def activate(self, ttl: float | None = None) -> str:
            _log(f"DummySessionManager.activate(ttl={ttl})")
            return "dummy"

        def invalidate(self, reason: str) -> None:
            _log(f"DummySessionManager.invalidate(reason={reason!r})")

        def require_active(self) -> str:
            return "dummy"

        def remaining_ttl(self) -> float:
            return 0.0

        def clear(self) -> None:
            _log("DummySessionManager.clear()")

    session_manager = _DummySessionManager()


try:
    from security.validation import (
        collect_issues,
        validate_file_path,
        validate_password,
    )
except Exception:  # pragma: no cover

    class _Issue:
        def __init__(self, field: str, message: str):
            self.field = field
            self.message = message

    def validate_file_path(path: str, must_exist: bool = True):
        if not path:
            return [_Issue("file", "Укажите путь к файлу.")]
        return []

    def validate_password(password: str):
        if len(password) < 8:
            return [_Issue("password", "Минимальная длина пароля — 8 символов.")]
        return []

    def collect_issues(*groups):
        issues = []
        for group in groups:
            issues.extend(group or [])
        return issues


try:
    from security.runtime_checks import SecurityIssue, run_environment_checks
except Exception:  # pragma: no cover

    class SecurityIssue:
        def __init__(self, severity: str, message: str):
            self.severity = severity
            self.message = message

    def run_environment_checks():
        return []


try:
    from ui.wizard import WizardController, WizardStep
except Exception:  # pragma: no cover

    class WizardStep:
        def __init__(self, title: str, on_enter=None, on_complete=None):
            self.title = title
            self.on_enter = on_enter or (lambda: None)
            self.on_complete = on_complete or (lambda: None)

    class WizardController:
        def __init__(self, steps, on_finish=None):
            self._steps = list(steps)
            self._index = 0
            self._on_finish = on_finish or (lambda: None)

        def start(self):
            if self._steps:
                self._steps[0].on_enter()

        def complete_current(self):
            if self._index >= len(self._steps):
                return
            step = self._steps[self._index]
            step.on_complete()
            self._index += 1
            if self._index < len(self._steps):
                self._steps[self._index].on_enter()
            else:
                self._on_finish()


try:
    from workflow.recipes import Recipe, Step, registry
except Exception:  # pragma: no cover

    class Step:
        def __init__(self, name: str, action):
            self.name = name
            self.action = action

    class Recipe:
        def __init__(self, name: str, steps):
            self.name = name
            self.steps = steps

    class _Registry:
        def register(self, recipe: Recipe):
            _log(f"Recipe registered (fallback): {recipe.name}")

    registry = _Registry()


try:
    from security.watchdog import EnvironmentWatchdog
except Exception:  # pragma: no cover

    class EnvironmentWatchdog:
        def __init__(self, *_, **__):
            _log("EnvironmentWatchdog disabled (fallback)")

        def start(self):
            _log("EnvironmentWatchdog.start() ignored (fallback)")

        def stop(self):
            _log("EnvironmentWatchdog.stop() ignored (fallback)")


# Публичные алиасы
record_event = _record_event
entropy_bits = _entropy_bits
verify_container = _verify_container
SecureFileController = _SecureFileController
authenticate = _authenticate


# ---------------------------------------------------------------------------
# KV-РАЗМЕТКА
# ---------------------------------------------------------------------------

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
                disabled: root.busy

            MDRaisedButton:
                text: "Распаковать"
                on_release: root.start_unpack()
                disabled: root.busy

            MDFlatButton:
                text: "Метаданные"
                on_release: root.show_metadata()
                disabled: root.busy

        MDFlatButton:
            text: "Отмена операции"
            on_release: root.cancel_operation()
            disabled: not root.busy

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


# ---------------------------------------------------------------------------
# ЭКРАН БЛОКИРОВКИ
# ---------------------------------------------------------------------------

class LockScreen(Screen):
    _dialog: Optional[MDDialog] = None
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
            Clock.schedule_once(lambda *_: setattr(self.manager, "current", "main"))

        def _failure(reason: str) -> None:
            button = MDFlatButton(text="OK")
            dialog = MDDialog(title="Биометрия", text=reason, buttons=[button])
            button.bind(on_release=lambda *_: dialog.dismiss())
            dialog.open()

        authenticate("Подтвердите личность", on_success=_success, on_failure=_failure)

    def report_issues(self, issues: List[SecurityIssue]) -> None:
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


# ---------------------------------------------------------------------------
# ОСНОВНОЙ ЭКРАН
# ---------------------------------------------------------------------------

class MainScreen(Screen):
    busy = BooleanProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.progress_bar: Optional[MDProgressBar] = None
        self.status_label: Optional[MDLabel] = None
        self.ttl_label: Optional[MDLabel] = None
        self.controller = SecureFileController()
        self._wizard: Optional[WizardController] = None
        self._ttl_event = None

    def on_kv_post(self, base_widget):
        self.progress_bar = self.ids.progress
        self.status_label = self.ids.status
        self.ttl_label = self.ids.ttl_status

        self._update_session_ttl()
        if self._ttl_event is None:
            self._ttl_event = Clock.schedule_interval(self._update_session_ttl, 1.0)

    # --- helpers ---

    def _set_status(self, text: str) -> None:
        if self.status_label:
            self.status_label.text = text

    def _set_progress(self, value: float) -> None:
        if self.progress_bar:
            self.progress_bar.value = value

    def _update_session_ttl(self, *_args) -> None:
        ttl = session_manager.remaining_ttl()
        if self.ttl_label:
            if ttl <= 0:
                self.ttl_label.text = "Сессия: заблокирована"
            else:
                self.ttl_label.text = f"Сессия: {int(ttl)}с"

    def _show_dialog(self, title: str, text: str) -> None:
        button = MDFlatButton(text="OK")
        dialog = MDDialog(title=title, text=text, buttons=[button])
        button.bind(on_release=lambda *_: dialog.dismiss())
        dialog.open()

    # --- wizard ---

    def _run_wizard(self, *, on_finish: Callable[[], None]) -> None:
        password = self.ids.password.text

        def _enter_validation() -> None:
            self._set_status("Валидация параметров...")

        def _complete_validation() -> None:
            self._set_status("Параметры подтверждены")

        def _enter_entropy() -> None:
            self._set_status("Оценка энтропии пароля...")
            bits = int(entropy_bits(password))
            self._show_dialog("Энтропия", f"Оценка энтропии: {bits} бит")

        steps = [
            WizardStep(title="validation", on_enter=_enter_validation, on_complete=_complete_validation),
            WizardStep(title="entropy", on_enter=_enter_entropy, on_complete=lambda: None),
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
            Clock.schedule_once(lambda *_: wizard_ref.complete_current(), (index + 1) * 0.05)

    # --- operations ---

    def cancel_operation(self) -> None:
        self.controller.cancel()
        self._set_status("Операция отменена")
        self._set_progress(0)
        self.busy = False

    def _validate_common(self) -> Tuple[str, str, Optional[str]]:
        file_path = self.ids.file_path.text.strip()
        output_path = self.ids.output_path.text.strip() or (file_path + ".zilant")
        password = self.ids.password.text
        decoy_message = (self.ids.decoy.text or "").strip() or None

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
        try:
            file_path, output_path, decoy_message = self._validate_common()
        except ValueError:
            return

        def _finish_wizard() -> None:
            self._set_status("Запуск упаковки...")
            self._set_progress(0)
            self.busy = True

            try:
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
            except Exception as exc:  # мгновенная ошибка
                self._on_operation_complete(str(exc))

        self._run_wizard(on_finish=_finish_wizard)

    def start_unpack(self) -> None:
        try:
            file_path, output_path, _ = self._validate_common()
        except ValueError:
            return

        def _finish_wizard() -> None:
            self._set_status("Запуск распаковки...")
            self._set_progress(0)
            self.busy = True

            try:
                self.controller.unpack(
                    file_path,
                    output_path,
                    self.ids.password.text,
                    progress_cb=lambda value: Clock.schedule_once(
                        lambda *_: self._set_progress(value)
                    ),
                    completion_cb=self._on_operation_complete,
                )
            except Exception as exc:
                self._on_operation_complete(str(exc))

        self._run_wizard(on_finish=_finish_wizard)

    def _on_operation_complete(self, error: Optional[str]) -> None:
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
            file_path = self.ids.file_path.text.strip()
            if not file_path:
                raise ValueError("Укажите путь к контейнеру.")
            metadata = verify_container(file_path)
            text = "\n".join(f"{key}: {value}" for key, value in metadata.items())
            self._show_dialog("Метаданные", text)
        except (IntegrityError, ValueError) as exc:
            self._show_dialog("Ошибка метаданных", str(exc))


# ---------------------------------------------------------------------------
# ПРИЛОЖЕНИЕ
# ---------------------------------------------------------------------------

class ZilantPrimeApp(MDApp):
    watchdog: Optional[EnvironmentWatchdog] = None

    def build(self):
        self.title = "Zilant Prime Mobile"

        # На десктопе фиксируем окно, на Android не трогаем размер.
        if platform != "android":
            Window.size = (420, 760)

        apply_secure_window(Window)
        enforce_pause_lock(self)
        self._register_recipes()

        issues = run_environment_checks()
        sm: ScreenManager = Builder.load_string(KV)

        lock_screen: LockScreen = sm.get_screen("lock")
        main_screen: MainScreen = sm.get_screen("main")

        if issues:
            record_event(
                "security.environment",
                details={
                    "issues": [
                        {"severity": getattr(issue, "severity", "?"), "message": issue.message}
                        for issue in issues
                    ]
                },
            )
            lock_screen.report_issues(issues)
            if any(getattr(issue, "severity", "") == "critical" for issue in issues):
                session_manager.invalidate("Обнаружены угрозы среды при запуске")

        def _lockdown_handler(found_issues: List[SecurityIssue]) -> None:
            session_manager.invalidate("Watchdog заблокировал сессию")
            main_screen.controller.cancel()
            main_screen.busy = False
            main_screen._set_status("Среда небезопасна. Сессия заблокирована.")
            sm.current = "lock"
            lock_screen.lockdown = True
            lock_screen.report_issues(found_issues)

        self.watchdog = EnvironmentWatchdog(
            interval=10.0,
            scheduler=lambda fn: Clock.schedule_once(lambda *_: fn()),
            issue_handler=lock_screen.report_issues,
            lockdown_handler=_lockdown_handler,
        )
        self.watchdog.start()
        return sm

    def _register_recipes(self) -> None:
        registry.register(
            Recipe(
                name="default_pack",
                steps=[
                    Step(
                        name="audit.start",
                        action=lambda: record_event("recipe.audit", details={"mode": "start"}),
                    ),
                    Step(
                        name="audit.finish",
                        action=lambda: record_event("recipe.audit", details={"mode": "finish"}),
                    ),
                ],
            )
        )

    def on_stop(self) -> None:
        if self.watchdog:
            self.watchdog.stop()
        session_manager.clear()


if __name__ == "__main__":
    try:
        from android.permissions import Permission, request_permissions

        request_permissions(
            [Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE]
        )
    except Exception:
        pass

    ZilantPrimeApp().run()
