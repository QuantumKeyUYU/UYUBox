from __future__ import annotations

import sys
import traceback


def android_log(message: str) -> None:
    """Send diagnostics to Android logcat (and stderr as fallback)."""
    try:
        from jnius import autoclass

        Log = autoclass("android.util.Log")
        Log.e("UYUBox", message)
    except Exception:
        # If jnius is not available, at least log to stderr
        print(message, file=sys.stderr)


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

from audit.logger import record_event
from crypto_core.profiles import entropy_bits
from integrity.validator import IntegrityError, verify_container
from security.android_security import apply_secure_window, enforce_pause_lock
from security.biometric import authenticate
from security.controller import SecureFileController
from security.session import SessionError, session_manager
from security.validation import collect_issues, validate_file_path, validate_password
from security.runtime_checks import SecurityIssue, run_environment_checks
from ui.wizard import WizardController, WizardStep
from workflow.recipes import Recipe, Step, registry
from security.watchdog import EnvironmentWatchdog

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
            Clock.schedule_once(lambda *_: setattr(self.manager, "current", "main"))

        def _failure(reason: str) -> None:
            button = MDFlatButton(text="OK")
            dialog = MDDialog(title="Биометрия", text=reason, buttons=[button])
            button.bind(on_release=lambda *_: dialog.dismiss())
            dialog.open()

        authenticate("Подтвердите личность", on_success=_success, on_failure=_failure)

    def report_issues(self, issues: list[SecurityIssue]) -> None:
        if not issues:
            return
        messages = [f"• {issue.message}" for issue in issues]
        self.warning_text = "\n".join(messages)
        if any(issue.severity == "critical" for issue in issues):
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
        self.controller = SecureFileController()
        self._wizard: WizardController | None = None
        self._ttl_event = None

    def on_kv_post(self, base_widget):
        self.progress_bar = self.ids.progress
        self.status_label = self.ids.status
        self.ttl_label = self.ids.ttl_status
        self._update_session_ttl()
        if self._ttl_event is None:
            self._ttl_event = Clock.schedule_interval(self._update_session_ttl, 1.0)

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

    def _run_wizard(self, *, on_finish) -> None:
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


class ZilantPrimeApp(MDApp):
    watchdog: EnvironmentWatchdog | None = None

    def build(self):
        self.title = "Zilant Prime Mobile"
        Window.size = (420, 760)
        apply_secure_window(Window)
        enforce_pause_lock(self)
        self._register_recipes()
        issues = run_environment_checks()
        sm = Builder.load_string(KV)
        if issues:
            record_event(
                "security.environment",
                details={
                    "issues": [
                        {"severity": issue.severity, "message": issue.message}
                        for issue in issues
                    ]
                },
            )
            lock_screen: LockScreen = sm.get_screen("lock")
            lock_screen.report_issues(issues)
            if any(issue.severity == "critical" for issue in issues):
                session_manager.invalidate("Обнаружены угрозы среды при запуске")
        lock_screen = sm.get_screen("lock")
        main_screen: MainScreen = sm.get_screen("main")

        def _lockdown_handler(found_issues: list[SecurityIssue]) -> None:
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

    def on_stop(self) -> None:
        if self.watchdog:
            self.watchdog.stop()
        session_manager.clear()


if __name__ == "__main__":
    try:
        try:
            from android.permissions import Permission, request_permissions

            request_permissions(
                [
                    Permission.READ_EXTERNAL_STORAGE,
                    Permission.WRITE_EXTERNAL_STORAGE,
                ]
            )
        except Exception:
            # Don't crash if permissions cannot be requested
            pass

        ZilantPrimeApp().run()

    except Exception:
        tb = traceback.format_exc()
        android_log(tb)
        print(tb, file=sys.stderr)
