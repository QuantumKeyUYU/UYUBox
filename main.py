from __future__ import annotations

from kivy.clock import Clock
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty
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
from security.validation import collect_issues, validate_file_path, validate_password
from ui.wizard import WizardController, WizardStep
from workflow.recipes import Recipe, Step, registry

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
        MDFlatButton:
            text: "Биометрия"
            pos_hint: {"center_x": .5, "center_y": .35}
            on_release: root.request_biometrics()

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
"""


class LockScreen(Screen):
    _dialog: MDDialog | None = None

    def unlock(self) -> None:
        self.manager.current = "main"

    def request_biometrics(self) -> None:
        def _success() -> None:
            Clock.schedule_once(lambda *_: setattr(self.manager, "current", "main"))

        def _failure(reason: str) -> None:
            button = MDFlatButton(text="OK")
            dialog = MDDialog(title="Биометрия", text=reason, buttons=[button])
            button.bind(on_release=lambda *_: dialog.dismiss())
            dialog.open()

        authenticate("Подтвердите личность", on_success=_success, on_failure=_failure)


class MainScreen(Screen):
    busy = BooleanProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.progress_bar: MDProgressBar | None = None
        self.status_label: MDLabel | None = None
        self.controller = SecureFileController()
        self._wizard: WizardController | None = None

    def on_kv_post(self, base_widget):
        self.progress_bar = self.ids.progress
        self.status_label = self.ids.status

    def _set_status(self, text: str) -> None:
        if self.status_label:
            self.status_label.text = text

    def _set_progress(self, value: float) -> None:
        if self.progress_bar:
            self.progress_bar.value = value

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
                progress_cb=lambda value: Clock.schedule_once(lambda *_: self._set_progress(value)),
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
                progress_cb=lambda value: Clock.schedule_once(lambda *_: self._set_progress(value)),
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
    def build(self):
        self.title = "Zilant Prime Mobile"
        Window.size = (420, 760)
        apply_secure_window(Window)
        enforce_pause_lock(self)
        self._register_recipes()
        sm = Builder.load_string(KV)
        return sm

    def _register_recipes(self) -> None:
        registry.register(
            Recipe(
                name="default_pack",
                steps=[
                    Step(name="audit.start", action=lambda: record_event("recipe.audit", details={"mode": "start"})),
                    Step(name="audit.finish", action=lambda: record_event("recipe.audit", details={"mode": "finish"})),
                ],
            )
        )


if __name__ == "__main__":
    try:
        from android.permissions import Permission, request_permissions

        request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])
    except Exception:
        pass
    ZilantPrimeApp().run()
