from __future__ import annotations

from kivy.clock import Clock
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty, StringProperty
from kivy.uix.screenmanager import Screen, ScreenManager, NoTransition

from kivymd.app import MDApp
from kivymd.uix.button import MDFlatButton, MDRaisedButton
from kivymd.uix.dialog import MDDialog
from kivymd.uix.label import MDLabel
from kivymd.uix.progressbar import MDProgressBar
from kivymd.uix.snackbar import Snackbar

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
<LockScreen>:
    name: "lock"
    MDFloatLayout:
        md_bg_color: app.theme_cls.bg_normal

        MDLabel:
            text: "Zilant Prime Mobile"
            halign: "center"
            pos_hint: {"center_x": .5, "center_y": .7}
            font_style: "H4"

        MDLabel:
            text: root.warning_text if root.warning_text else "Сессия заблокирована. Подтвердите доступ."
            halign: "center"
            theme_text_color: "Secondary"
            pos_hint: {"center_x": .5, "center_y": .6}
            size_hint_x: .8
            text_size: self.width, None

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
            text: "Среда: небезопасна" if root.lockdown else "Среда: ок"
            halign: "center"
            pos_hint: {"center_x": .5, "center_y": .2}
            theme_text_color: "Error" if root.lockdown else "Secondary"


<MainScreen>:
    name: "main"
    MDBoxLayout:
        orientation: "vertical"

        MDLabel:
            id: ttl_status
            text: "Сессия: —"
            halign: "left"
            theme_text_color: "Secondary"
            size_hint_y: None
            height: dp(32)
            padding_x: dp(16)

        MDTabs:
            id: tabs
            on_tab_switch: root.on_tab_switch(*args)

            MDTabsItem:
                title: "Файл"
                MDBoxLayout:
                    orientation: "vertical"
                    padding: dp(16)
                    spacing: dp(12)

                    MDTextField:
                        id: file_path
                        hint_text: "Источник (файл/контейнер)"
                        helper_text: "Укажи путь к файлу или контейнеру"
                        helper_text_mode: "on_focus"

                    MDTextField:
                        id: output_path
                        hint_text: "Выходной файл"
                        helper_text: "Путь для результата (по умолчанию *.zilant)"
                        helper_text_mode: "on_focus"

                    MDTextField:
                        id: password
                        hint_text: "Пароль"
                        password: True
                        on_text: root.on_password_changed(self.text)

                    MDLabel:
                        id: entropy_label
                        text: "Энтропия: —"
                        theme_text_color: "Secondary"
                        size_hint_y: None
                        height: dp(24)

                    MDTextField:
                        id: decoy
                        hint_text: "Decoy-сообщение (опционально)"

                    MDBoxLayout:
                        size_hint_y: None
                        height: dp(48)
                        spacing: dp(12)

                        MDRaisedButton:
                            text: "Зашифровать"
                            on_release: root.start_pack()

                        MDRaisedButton:
                            text: "Расшифровать"
                            on_release: root.start_unpack()

                        MDFlatButton:
                            text: "Метаданные"
                            on_release: root.show_metadata()

                    MDProgressBar:
                        id: progress
                        value: 0
                        max: 1

                    MDBoxLayout:
                        size_hint_y: None
                        height: dp(48)
                        spacing: dp(12)

                        MDFlatButton:
                            text: "Отмена операции"
                            on_release: root.cancel_operation()

                    MDLabel:
                        id: status
                        text: "Готово"
                        halign: "left"
                        theme_text_color: "Secondary"

            MDTabsItem:
                title: "Текст"
                MDBoxLayout:
                    orientation: "vertical"
                    padding: dp(16)
                    spacing: dp(12)

                    MDTextField:
                        id: text_plain
                        hint_text: "Открытый текст"
                        multiline: True

                    MDTextField:
                        id: text_cipher
                        hint_text: "Зашифрованный блок (Base64)"
                        multiline: True

                    MDBoxLayout:
                        size_hint_y: None
                        height: dp(48)
                        spacing: dp(12)

                        MDRaisedButton:
                            text: "Шифровать"
                            on_release: root.encrypt_text()

                        MDRaisedButton:
                            text: "Расшифровать"
                            on_release: root.decrypt_text()

            MDTabsItem:
                title: "Настройки"
                MDBoxLayout:
                    orientation: "vertical"
                    padding: dp(16)
                    spacing: dp(12)

                    MDLabel:
                        text: "Профиль безопасности"
                        size_hint_y: None
                        height: dp(24)

                    MDSegmentedControl:
                        id: profile_control
                        size_hint_y: None
                        height: dp(40)
                        on_active: root.on_profile_changed(self, *args)
                        MDSegmentedControlItem:
                            text: "Normal"
                        MDSegmentedControlItem:
                            text: "Paranoid"

                    MDLabel:
                        text: "Управление"
                        size_hint_y: None
                        height: dp(24)

                    MDRaisedButton:
                        text: "Перепроверить среду"
                        on_release: root.manual_env_check()

                    MDRaisedButton:
                        text: "Сбросить сессию"
                        on_release: root.reset_session()
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
            dialog = MDDialog(
                title="Биометрия",
                text=reason,
                buttons=[MDFlatButton(text="OK", on_release=lambda *_: dialog.dismiss())],
            )
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

    # ---------- общие утилиты ----------

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

    def _notify(self, text: str) -> None:
        Snackbar(text=text, duration=1.5).open()

    # ---------- UX callbacks ----------

    def on_tab_switch(self, *args):
        # можно писать аналитику по вкладкам
        pass

    def on_password_changed(self, password: str) -> None:
        if not password:
            self.ids.entropy_label.text = "Энтропия: —"
            return
        try:
            bits = int(entropy_bits(password))
            self.ids.entropy_label.text = f"Энтропия: {bits} бит"
        except Exception:
            self.ids.entropy_label.text = "Энтропия: недоступна"

    # ---------- wizard ----------

    def _run_wizard(self, *, on_finish) -> None:
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
            except Exception:
                self._show_dialog("Энтропия", "Не удалось оценить энтропию.")

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

    # ---------- операции с файлами ----------

    def cancel_operation(self) -> None:
        self.controller.cancel()
        self._set_status("Операция отменена")
        self._set_progress(0)
        self.busy = False
        self._notify("Отменено")

    def _validate_common(self) -> tuple[str, str, str | None]:
        file_path = self.ids.file_path.text.strip()
        output_path = self.ids.output_path.text.strip() or (file_path + ".zilant")
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
            self._show_dialog("Ошибки параметров", text)
            raise ValueError(text)

        return file_path, output_path, decoy_message

    def start_pack(self) -> None:
        try:
            file_path, output_path, decoy_message = self._validate_common()
        except ValueError:
            return

        def _finish_wizard() -> None:
            self._set_status("Запуск шифрования...")
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
            self._set_status("Запуск расшифровки...")
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
                self._show_dialog("Ошибка операции", error)
            else:
                self._set_status("Операция завершена")
                record_event("ui.operation.complete", details={"screen": "main"})
                self._notify("Готово")
            self._set_progress(0)

        Clock.schedule_once(_update)

    def show_metadata(self) -> None:
        try:
            file_path = self.ids.file_path.text.strip()
            if not file_path:
                raise ValueError("Укажите путь к контейнеру.")
            metadata = verify_container(file_path)
            text = "\n".join(f"{key}: {value}" for key, value in metadata.items())
            self._show_dialog("Метаданные контейнера", text)
        except (IntegrityError, ValueError) as exc:
            self._show_dialog("Ошибка метаданных", str(exc))

    # ---------- операции с текстом ----------

    def encrypt_text(self) -> None:
        # здесь ты можешь использовать тот же SecureFileController или
        # отдельный текстовый API из zilant-prime-core
        try:
            session_manager.require_active()
        except SessionError as exc:
            self._show_dialog("Сессия заблокирована", str(exc))
            return

        plain = self.ids.text_plain.text or ""
        if not plain:
            self._notify("Нет текста для шифрования")
            return

        password = self.ids.password.text
        issues = collect_issues(validate_password(password))
        if issues:
            text = "\n".join(f"{issue.field}: {issue.message}" for issue in issues)
            self._show_dialog("Пароль", text)
            return

        try:
            # заглушка: тут зови реальный API ядра
            from crypto_core.api import encrypt_text  # примерный модуль

            cipher_b64 = encrypt_text(plain, password)
            self.ids.text_cipher.text = cipher_b64
            self._notify("Текст зашифрован")
        except Exception as exc:
            self._show_dialog("Ошибка шифрования текста", str(exc))

    def decrypt_text(self) -> None:
        try:
            session_manager.require_active()
        except SessionError as exc:
            self._show_dialog("Сессия заблокирована", str(exc))
            return

        cipher_b64 = self.ids.text_cipher.text or ""
        if not cipher_b64:
            self._notify("Нет данных для расшифровки")
            return

        password = self.ids.password.text
        try:
            from crypto_core.api import decrypt_text  # примерный модуль

            plain = decrypt_text(cipher_b64, password)
            self.ids.text_plain.text = plain
            self._notify("Текст расшифрован")
        except Exception as exc:
            self._show_dialog("Ошибка расшифровки текста", str(exc))

    # ---------- настройки ----------

    def on_profile_changed(self, control, *args):
        # тут можно переключать параметры argon2/политику TTL
        # например: Normal = 5 минут, Paranoid = 60 сек
        self._notify("Профиль безопасности изменён")

    def manual_env_check(self) -> None:
        issues = run_environment_checks()
        if not issues:
            self._show_dialog("Проверка среды", "Проблем не обнаружено.")
            return
        text = "\n".join(f"{issue.severity.upper()}: {issue.message}" for issue in issues)
        self._show_dialog("Проверка среды", text)

    def reset_session(self) -> None:
        session_manager.invalidate("Сброшено пользователем")
        self._notify("Сессия сброшена")


class ZilantPrimeApp(MDApp):
    watchdog: EnvironmentWatchdog | None = None

    def build(self):
        self.title = "Zilant Prime Mobile"
        self.theme_cls.primary_palette = "BlueGray"

        Window.size = (420, 760)
        apply_secure_window(Window)
        enforce_pause_lock(self)
        self._register_recipes()

        Builder.load_string(KV)
        sm = ScreenManager(transition=NoTransition())
        lock_screen = LockScreen()
        main_screen = MainScreen()
        sm.add_widget(lock_screen)
        sm.add_widget(main_screen)

        # стартовая проверка среды
        issues = run_environment_checks()
        if issues:
            record_event(
                "security.environment",
                details={"issues": [{"severity": i.severity, "message": i.message} for i in issues]},
            )
            lock_screen.report_issues(issues)
            if any(issue.severity == "critical" for issue in issues):
                session_manager.invalidate("Обнаружены угрозы среды при запуске")

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

        request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])
    except Exception:
        pass

    ZilantPrimeApp().run()
