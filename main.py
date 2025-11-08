from __future__ import annotations

import os
import tempfile
import time

from kivy.clock import Clock
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty, StringProperty
from kivy.uix.screenmanager import Screen
from kivy.utils import platform

from kivymd.app import MDApp
from kivymd.uix.appbar import MDTopAppBar
from kivymd.uix.button import MDFlatButton, MDRaisedButton
from kivymd.uix.dialog import MDDialog
from kivymd.uix.filemanager import MDFileManager
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
from security.watchdog import EnvironmentWatchdog
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

        MDLabel:
            text: root.warning_text
            halign: "center"
            theme_text_color: "Error"
            size_hint_x: .9
            pos_hint: {"center_x": .5, "center_y": .15}
            text_size: self.width, None
            height: self.texture_size[1] if self.texture_size[1] else 0
            font_style: "Caption"

<MainScreen>:
    name: "main"
    MDBoxLayout:
        orientation: "vertical"

        MDTopAppBar:
            title: "UYUBox · Zilant Prime"
            elevation: 4

        MDScrollView:
            MDBoxLayout:
                id: content
                orientation: "vertical"
                padding: dp(16)
                spacing: dp(16)
                size_hint_y: None
                height: self.minimum_height

                MDCard:
                    orientation: "vertical"
                    padding: dp(12)
                    spacing: dp(8)
                    size_hint_y: None
                    height: self.minimum_height

                    MDLabel:
                        text: "Файловый контейнер"
                        bold: True
                        theme_text_color: "Primary"

                    MDTextField:
                        id: file_path
                        hint_text: "Файл / контейнер"
                        helper_text: "Выберите файл или контейнер .zilant"
                        helper_text_mode: "on_focus"

                    MDTextField:
                        id: output_path
                        hint_text: "Выходной контейнер (.zilant)"

                    MDBoxLayout:
                        size_hint_y: None
                        height: dp(40)
                        spacing: dp(8)
                        MDRaisedButton:
                            text: "Выбрать файл"
                            on_release: root.pick_file_for("file_path")
                        MDRaisedButton:
                            text: "Выход..."
                            on_release: root.pick_file_for("output_path")

                    MDBoxLayout:
                        size_hint_y: None
                        height: dp(40)
                        spacing: dp(8)
                        MDRaisedButton:
                            text: "Упаковать"
                            on_release: root.start_pack()
                        MDRaisedButton:
                            text: "Распаковать"
                            on_release: root.start_unpack()
                        MDFlatButton:
                            text: "Метаданные"
                            on_release: root.show_metadata()

                MDCard:
                    orientation: "vertical"
                    padding: dp(12)
                    spacing: dp(8)
                    size_hint_y: None
                    height: self.minimum_height

                    MDLabel:
                        text: "Пароль и сеанс"
                        bold: True

                    MDTextField:
                        id: password
                        hint_text: "Пароль"
                        password: True
                        on_text: root.update_password_strength(self.text)

                    MDProgressBar:
                        id: pw_strength
                        value: 0
                        max: 128
                        size_hint_y: None
                        height: dp(4)

                    MDLabel:
                        id: pw_strength_label
                        text: "Энтропия: —"
                        theme_text_color: "Secondary"
                        font_style: "Caption"

                    MDTextField:
                        id: decoy
                        hint_text: "Decoy-сообщение (опционально)"

                    MDLabel:
                        id: ttl_status
                        text: "Сессия: —"
                        theme_text_color: "Secondary"
                        font_style: "Caption"

                MDCard:
                    orientation: "vertical"
                    padding: dp(12)
                    spacing: dp(8)
                    size_hint_y: None
                    height: self.minimum_height

                    MDLabel:
                        text: "Текст через контейнер"
                        bold: True

                    MDTextField:
                        id: text_input
                        hint_text: "Текст для шифрования"
                        multiline: True

                    MDTextField:
                        id: text_container
                        hint_text: "Контейнер для текста (.zilant)"

                    MDBoxLayout:
                        size_hint_y: None
                        height: dp(40)
                        spacing: dp(8)
                        MDRaisedButton:
                            text: "Выбрать контейнер"
                            on_release: root.pick_file_for("text_container")
                        MDRaisedButton:
                            text: "Зашифровать"
                            on_release: root.encrypt_text_to_container()
                        MDRaisedButton:
                            text: "Расшифровать"
                            on_release: root.decrypt_text_from_container()

                    MDTextField:
                        id: text_output
                        hint_text: "Расшифрованный текст"
                        multiline: True

        MDBoxLayout:
            size_hint_y: None
            height: dp(68)
            padding: dp(12)
            spacing: dp(12)
            orientation: "vertical"

            MDProgressBar:
                id: progress
                value: 0
                max: 1

            MDBoxLayout:
                orientation: "horizontal"
                spacing: dp(8)

                MDLabel:
                    id: status
                    text: "Готово"
                    halign: "left"
                    shorten: True

                MDFlatButton:
                    text: "Отмена"
                    on_release: root.cancel_operation()
"""


class LockScreen(Screen):
    _dialog: MDDialog | None = None
    warning_text = StringProperty("")

    def unlock(self) -> None:
        # Простая активация сессии, без “кирпичного” lockdown
        session_manager.activate()
        record_event("ui.unlock", details={"method": "passcode"})
        self.manager.current = "main"

    def request_biometrics(self) -> None:
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
            self.warning_text = ""
            return
        messages = [f"• {issue.message}" for issue in issues]
        self.warning_text = "\n".join(messages)

        # Тут **не** блокируем насмерть, только предупреждаем.
        # Строгий режим можно будет вернуть, когда всё отполируем.
        record_event(
            "security.environment.warning",
            details={
                "issues": [
                    {"severity": i.severity, "message": i.message}
                    for i in issues
                ]
            },
        )


class MainScreen(Screen):
    busy = BooleanProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.progress_bar: MDProgressBar | None = None
        self.status_label: MDLabel | None = None
        self.ttl_label: MDLabel | None = None
        self.pw_bar: MDProgressBar | None = None
        self.pw_label: MDLabel | None = None

        self.controller = SecureFileController()
        self._wizard: WizardController | None = None
        self._ttl_event = None

        self.file_manager: MDFileManager | None = None
        self._file_pick_target: str | None = None

    def on_kv_post(self, base_widget):
        self.progress_bar = self.ids.progress
        self.status_label = self.ids.status
        self.ttl_label = self.ids.ttl_status
        self.pw_bar = self.ids.pw_strength
        self.pw_label = self.ids.pw_strength_label

        self._update_session_ttl()
        if self._ttl_event is None:
            self._ttl_event = Clock.schedule_interval(self._update_session_ttl, 1.0)

        # Файловый менеджер
        self.file_manager = MDFileManager(
            select_path=self._on_file_manager_select,
            exit_manager=self._on_file_manager_close,
            preview=False,
        )

    # ---------- утилиты UI ----------

    def _set_status(self, text: str) -> None:
        if self.status_label:
            self.status_label.text = text

    def _set_progress(self, value: float) -> None:
        if self.progress_bar:
            self.progress_bar.value = value

    def _update_session_ttl(self, *_args) -> None:
        ttl = session_manager.remaining_ttl()
        if not self.ttl_label:
            return
        if ttl <= 0:
            self.ttl_label.text = "Сессия: заблокирована"
        else:
            self.ttl_label.text = f"Сессия: {int(ttl)}с"

    def _show_dialog(self, title: str, text: str) -> None:
        button = MDFlatButton(text="OK")
        dialog = MDDialog(title=title, text=text, buttons=[button])
        button.bind(on_release=lambda *_: dialog.dismiss())
        dialog.open()

    # ---------- файловый менеджер ----------

    def pick_file_for(self, target_id: str) -> None:
        if not self.file_manager:
            return
        self._file_pick_target = target_id

        if platform == "android":
            start_path = "/storage/emulated/0"
        else:
            start_path = os.path.expanduser("~")

        try:
            self.file_manager.show(start_path)
        except Exception as exc:
            self._show_dialog("Ошибка файлового менеджера", str(exc))

    def _on_file_manager_select(self, path: str) -> None:
        if self._file_pick_target and self._file_pick_target in self.ids:
            self.ids[self._file_pick_target].text = path
        self._on_file_manager_close()

    def _on_file_manager_close(self, *args) -> None:
        if self.file_manager:
            self.file_manager.close()

    # ---------- пароль и энтропия ----------

    def update_password_strength(self, password: str) -> None:
        if not self.pw_bar or not self.pw_label:
            return
        try:
            bits = int(entropy_bits(password)) if password else 0
        except Exception:
            bits = 0

        self.pw_bar.value = bits

        if bits == 0:
            quality = "—"
        elif bits < 40:
            quality = "низкая"
        elif bits < 80:
            quality = "средняя"
        elif bits < 110:
            quality = "высокая"
        else:
            quality = "параноидальная"

        if bits == 0:
            self.pw_label.text = "Энтропия: —"
        else:
            self.pw_label.text = f"Энтропия: {bits} бит ({quality})"

    # ---------- общий контроль сессии/параметров ----------

    def _require_session_and_password(self) -> str:
        password = self.ids.password.text

        try:
            session_manager.require_active()
        except SessionError as exc:
            self._show_dialog("Сессия заблокирована", str(exc))
            raise ValueError(str(exc)) from exc

        issues = collect_issues(
            validate_password(password),
        )
        if issues:
            text = "\n".join(f"{issue.field}: {issue.message}" for issue in issues)
            self._show_dialog("Ошибка пароля", text)
            raise ValueError(text)
        return password

    def _validate_common_file(self) -> tuple[str, str, str | None, str]:
        file_path = self.ids.file_path.text.strip()
        output_path = self.ids.output_path.text.strip()
        if not output_path and file_path:
            output_path = file_path + ".zilant"

        password = self._require_session_and_password()
        decoy_message = self.ids.decoy.text or None

        issues = collect_issues(
            validate_file_path(file_path, must_exist=True),
        )
        if issues:
            text = "\n".join(f"{issue.field}: {issue.message}" for issue in issues)
            self._show_dialog("Ошибки пути", text)
            raise ValueError(text)

        return file_path, output_path, decoy_message, password

    # ---------- мастер-«визард» перед операцией ----------

    def _run_wizard(self, *, on_finish) -> None:
        password = self.ids.password.text

        def _enter_validation() -> None:
            self._set_status("Валидация параметров...")

        def _complete_validation() -> None:
            self._set_status("Параметры подтверждены")

        def _enter_entropy() -> None:
            self._set_status("Оценка энтропии пароля...")
            bits = int(entropy_bits(password)) if password else 0
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

    # ---------- отмена ----------

    def cancel_operation(self) -> None:
        self.controller.cancel()
        self._set_status("Операция отменена")
        self._set_progress(0)
        self.busy = False

    # ---------- файловые операции ----------

    def start_pack(self) -> None:
        if self.busy:
            return
        try:
            file_path, output_path, decoy_message, password = self._validate_common_file()
        except ValueError:
            return

        def _finish_wizard() -> None:
            self._set_status("Запуск упаковки...")
            self._set_progress(0)
            self.busy = True
            self.controller.pack(
                file_path,
                output_path,
                password,
                decoy_message=decoy_message,
                progress_cb=lambda value: Clock.schedule_once(lambda *_: self._set_progress(value)),
                completion_cb=self._on_operation_complete,
            )

        self._run_wizard(on_finish=_finish_wizard)

    def start_unpack(self) -> None:
        if self.busy:
            return
        try:
            file_path, output_path, _decoy, password = self._validate_common_file()
        except ValueError:
            return

        def _finish_wizard() -> None:
            self._set_status("Запуск распаковки...")
            self._set_progress(0)
            self.busy = True
            self.controller.unpack(
                file_path,
                output_path,
                password,
                progress_cb=lambda value: Clock.schedule_once(lambda *_: self._set_progress(value)),
                completion_cb=self._on_operation_complete,
            )

        self._run_wizard(on_finish=_finish_wizard)

    def _on_operation_complete(self, error: str | None) -> None:
        def _update(_dt):
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

    # ---------- текст через контейнер ----------

    def _default_container_dir(self) -> str:
        if platform == "android":
            try:
                from android.storage import primary_external_storage_path

                return primary_external_storage_path()
            except Exception:
                pass
        return os.path.expanduser("~")

    def encrypt_text_to_container(self) -> None:
        if self.busy:
            return
        text = self.ids.text_input.text
        if not text.strip():
            self._show_dialog("Нет текста", "Введите текст для шифрования.")
            return

        try:
            password = self._require_session_and_password()
        except ValueError:
            return

        container_path = self.ids.text_container.text.strip()
        if not container_path:
            base_dir = self._default_container_dir()
            name = f"zilant_text_{int(time.time())}.zilant"
            container_path = os.path.join(base_dir, name)
            self.ids.text_container.text = container_path

        # временный файл с открытым текстом
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp_path = tmp.name
        tmp.write(text.encode("utf-8"))
        tmp.close()

        decoy_message = self.ids.decoy.text or None

        def _start() -> None:
            self._set_status("Шифрование текста в контейнер...")
            self._set_progress(0)
            self.busy = True

            def _complete(error: str | None) -> None:
                def _finish(_dt):
                    self.busy = False
                    try:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    except Exception:
                        pass

                    if error:
                        self._set_status(f"Ошибка: {error}")
                        self._show_dialog("Ошибка", error)
                    else:
                        self._set_status(f"Текст зашифрован в {container_path}")
                        record_event("ui.text.encrypt", details={"container": container_path})
                        self._show_dialog("Успех", f"Текст зашифрован в контейнер:\n{container_path}")
                    self._set_progress(0)

                Clock.schedule_once(_finish)

            self.controller.pack(
                tmp_path,
                container_path,
                password,
                decoy_message=decoy_message,
                progress_cb=lambda v: Clock.schedule_once(lambda *_: self._set_progress(v)),
                completion_cb=_complete,
            )

        self._run_wizard(on_finish=_start)

    def decrypt_text_from_container(self) -> None:
        if self.busy:
            return
        container_path = self.ids.text_container.text.strip()
        if not container_path:
            self._show_dialog("Нет контейнера", "Выберите контейнер с текстом.")
            return

        try:
            password = self._require_session_and_password()
        except ValueError:
            return

        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp_path = tmp.name
        tmp.close()

        def _start() -> None:
            self._set_status("Расшифровка текста из контейнера...")
            self._set_progress(0)
            self.busy = True

            def _complete(error: str | None) -> None:
                def _finish(_dt):
                    self.busy = False
                    if error:
                        self._set_status(f"Ошибка: {error}")
                        self._show_dialog("Ошибка", error)
                        try:
                            if os.path.exists(tmp_path):
                                os.unlink(tmp_path)
                        except Exception:
                            pass
                    else:
                        try:
                            with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
                                text = f.read()
                        except Exception as exc:
                            text = ""
                            self._show_dialog("Ошибка чтения", str(exc))
                        finally:
                            try:
                                if os.path.exists(tmp_path):
                                    os.unlink(tmp_path)
                            except Exception:
                                pass

                        self.ids.text_output.text = text
                        self._set_status("Текст расшифрован")
                        record_event("ui.text.decrypt", details={"container": container_path})
                    self._set_progress(0)

                Clock.schedule_once(_finish)

            self.controller.unpack(
                container_path,
                tmp_path,
                password,
                progress_cb=lambda v: Clock.schedule_once(lambda *_: self._set_progress(v)),
                completion_cb=_complete,
            )

        self._run_wizard(on_finish=_start)


class ZilantPrimeApp(MDApp):
    watchdog: EnvironmentWatchdog | None = None

    def build(self):
        self.title = "Zilant Prime Mobile"

        # НЕ трогаем размер окна на Android, чтобы не было миниатюры в углу
        if platform in ("win", "linux", "macosx"):
            Window.size = (420, 760)

        apply_secure_window(Window)
        enforce_pause_lock(self)

        self._register_recipes()

        issues = run_environment_checks()
        sm = Builder.load_string(KV)

        lock_screen: LockScreen = sm.get_screen("lock")
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
            lock_screen.report_issues(issues)

        main_screen: MainScreen = sm.get_screen("main")

        def _lockdown_handler(found_issues: list[SecurityIssue]) -> None:
            # “Мягкий” режим: выкидываем на экран блокировки и инвалидируем сессию,
            # но не превращаем приложение в кирпич.
            session_manager.invalidate("Watchdog потребовал повторную аутентификацию")
            main_screen.controller.cancel()
            main_screen.busy = False
            main_screen._set_status("Среда изменилась. Требуется повторная разблокировка.")
            sm.current = "lock"
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
