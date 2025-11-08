from __future__ import annotations

import os
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
from kivymd.uix.filemanager import MDFileManager
from kivymd.uix.snackbar import Snackbar

# твои модули
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

DEV_OVERRIDE = os.environ.get("ZILANT_DEV", "1") == "1"  # по умолчанию включён для удобства

KV = """
#:import dp kivy.metrics.dp

ScreenManager:
    LockScreen:
    MainScreen:

<LockScreen>:
    name: "lock"
    MDFloatLayout:
        md_bg_color: app.theme_cls.bg_normal
        MDLabel:
            id: logo
            text: "Zilant Prime Mobile"
            halign: "center"
            pos_hint: {"center_x": .5, "center_y": .74}
            font_style: "H4"
        MDLabel:
            text: root.env_badge
            halign: "center"
            pos_hint: {"center_x": .5, "center_y": .66}
            theme_text_color: "Secondary"
            font_style: "Caption"
        MDRaisedButton:
            text: "Разблокировать"
            pos_hint: {"center_x": .5, "center_y": .5}
            on_release: root.unlock()
            disabled: root.lockdown and not app.dev_override
        MDFlatButton:
            text: "Биометрия"
            pos_hint: {"center_x": .5, "center_y": .42}
            on_release: root.request_biometrics()
            disabled: root.lockdown and not app.dev_override
        MDLabel:
            text: root.warning_text
            halign: "center"
            theme_text_color: "Error"
            size_hint_y: None
            pos_hint: {"center_x": .5, "center_y": .28}
            text_size: self.width - dp(32), None
            height: self.texture_size[1] if self.texture_size[1] else 0
        MDLabel:
            text: "Тройной тап по заголовку — dev-разблокировка"
            halign: "center"
            pos_hint: {"center_x": .5, "center_y": .16}
            theme_text_color: "Secondary"
            font_style: "Caption"

<MainScreen>:
    name: "main"
    padding: dp(12)
    MDBoxLayout:
        orientation: "vertical"
        spacing: dp(10)

        MDTextField:
            id: file_path
            hint_text: "Путь к файлу / контейнеру"
            helper_text: "Нажми «Выбрать файл» ниже"
            helper_text_mode: "on_focus"

        MDBoxLayout:
            adaptive_height: True
            spacing: dp(8)
            MDRaisedButton:
                text: "Выбрать файл"
                on_release: root.pick_file()
            MDFlatButton:
                text: "Очистить"
                on_release: root.clear_file()

        MDTextField:
            id: output_path
            hint_text: "Выходной файл (.zilant — по умолчанию)"

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
            adaptive_height: True
            spacing: dp(10)
            MDRaisedButton:
                text: "Упаковать"
                on_release: root.start_pack()
            MDRaisedButton:
                text: "Распаковать"
                on_release: root.start_unpack()
            MDFlatButton:
                text: "Метаданные"
                on_release: root.show_metadata()

        MDLabel:
            id: status
            text: "Готово"
            halign: "left"

        MDLabel:
            id: ttl_status
            text: "Сессия: —"
            halign: "left"
            theme_text_color: "Secondary"

        MDBoxLayout:
            adaptive_height: True
            spacing: dp(8)
            MDFlatButton:
                text: "Отмена операции"
                on_release: root.cancel_operation()
"""

class LockScreen(Screen):
    lockdown = BooleanProperty(False)
    warning_text = StringProperty("")
    env_badge = StringProperty("")
    _dialog: MDDialog | None = None
    _taps = 0

    def on_kv_post(self, *_):
        # тройной тап по заголовку -> dev unlock
        label = self.ids.get("logo")
        if label:
            label.bind(on_touch_down=self._tap_unlock)

    def _tap_unlock(self, widget, touch):
        if not widget.collide_point(*touch.pos):
            return
        self._taps += 1
        if self._taps >= 3:
            self.lockdown = False
            Snackbar(text="Dev-разблокировка активирована").open()
            self._taps = 0

    def unlock(self) -> None:
        # в dev режиме всегда даём пройти
        if self.lockdown and not MDApp.get_running_app().dev_override:
            self._show_lockdown_dialog()
            return
        session_manager.activate()
        record_event("ui.unlock", details={"method": "passcode"})
        self.manager.current = "main"

    def request_biometrics(self) -> None:
        if self.lockdown and not MDApp.get_running_app().dev_override:
            self._show_lockdown_dialog()
            return

        def _success() -> None:
            session_manager.activate()
            record_event("ui.unlock", details={"method": "biometric"})
            Clock.schedule_once(lambda *_: setattr(self.manager, "current", "main"))

        def _failure(reason: str) -> None:
            self._simple_dialog("Биометрия", reason)

        authenticate("Подтвердите личность", on_success=_success, on_failure=_failure)

    def report_issues(self, issues: list[SecurityIssue]) -> None:
        if not issues:
            self.env_badge = "Среда: OK"
            return
        self.env_badge = "Среда: повышенный риск"
        self.warning_text = "\n".join(f"• {i.message}" for i in issues)
        # блокируем только при критике и если не dev
        if any(i.severity == "critical" for i in issues) and not MDApp.get_running_app().dev_override:
            self.lockdown = True
            session_manager.invalidate("Обнаружены критические проблемы среды")

    def _show_lockdown_dialog(self) -> None:
        if self._dialog:
            return
        btn = MDFlatButton(text="OK")
        dialog = MDDialog(
            title="Защита активна",
            text="Обнаружена небезопасная среда. Устраните угрозы или включите dev-разблокировку (тройной тап).",
            buttons=[btn],
        )
        btn.bind(on_release=lambda *_: dialog.dismiss())
        dialog.bind(on_dismiss=lambda *_: setattr(self, "_dialog", None))
        self._dialog = dialog
        dialog.open()

    def _simple_dialog(self, title: str, text: str) -> None:
        btn = MDFlatButton(text="OK")
        dialog = MDDialog(title=title, text=text, buttons=[btn])
        btn.bind(on_release=lambda *_: dialog.dismiss())
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
        self._fm: MDFileManager | None = None

    def on_kv_post(self, base_widget):
        self.progress_bar = self.ids.progress
        self.status_label = self.ids.status
        self.ttl_label = self.ids.ttl_status
        # файл-менеджер
        self._fm = MDFileManager(exit_manager=self._close_fm, select_path=self._select_path)
        self._fm.ext = [".txt", ".png", ".jpg", ".jpeg", ".pdf", ".mp4", ".zip", ".rar", ".7z", ".zilant", ".*"]
        # TTL
        self._update_session_ttl()
        if self._ttl_event is None:
            self._ttl_event = Clock.schedule_interval(self._update_session_ttl, 1.0)

    # ---------- UI helpers ----------
    def _set_status(self, text: str) -> None:
        if self.status_label:
            self.status_label.text = text

    def _set_progress(self, value: float) -> None:
        if self.progress_bar:
            self.progress_bar.value = value

    def _update_session_ttl(self, *_args) -> None:
        ttl = session_manager.remaining_ttl()
        if self.ttl_label:
            self.ttl_label.text = "Сессия: заблокирована" if ttl <= 0 else f"Сессия: {int(ttl)}с"

    def _dialog(self, title: str, text: str) -> None:
        btn = MDFlatButton(text="OK")
        dlg = MDDialog(title=title, text=text, buttons=[btn])
        btn.bind(on_release=lambda *_: dlg.dismiss())
        dlg.open()

    # ---------- File manager ----------
    def pick_file(self) -> None:
        try:
            start_path = "/sdcard" if os.path.isdir("/sdcard") else "/"
            self._fm.show(start_path)
        except Exception as e:
            self._dialog("Файл-менеджер", f"Не удалось открыть проводник: {e}")

    def _close_fm(self, *args) -> None:
        if self._fm:
            self._fm.close()

    def _select_path(self, path: str) -> None:
        self.ids.file_path.text = path
        # Предлагаем выходной путь
        base = path if path.endswith(".zilant") else f"{path}.zilant"
        if not self.ids.output_path.text:
            self.ids.output_path.text = base
        self._close_fm()
        Snackbar(text=f"Выбран файл: {os.path.basename(path)}").open()

    def clear_file(self) -> None:
        self.ids.file_path.text = ""
        Snackbar(text="Поле файла очищено").open()

    # ---------- Wizard & validation ----------
    def _run_wizard(self, *, on_finish) -> None:
        password = self.ids.password.text

        def _enter_validation() -> None:
            self._set_status("Валидация параметров...")

        def _complete_validation() -> None:
            self._set_status("Параметры подтверждены")

        def _enter_entropy() -> None:
            self._set_status("Оценка энтропии пароля...")
            bits = int(entropy_bits(password))
            self._dialog("Энтропия", f"Оценка энтропии: {bits} бит")

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

    def _validate_common(self) -> tuple[str, str, str | None]:
        file_path = self.ids.file_path.text.strip()
        output_path = self.ids.output_path.text.strip() or (file_path + ".zilant")
        password = self.ids.password.text
        decoy_message = self.ids.decoy.text or None

        try:
            session_manager.require_active()
        except SessionError as exc:
            self._dialog("Сессия заблокирована", str(exc))
            raise ValueError(str(exc)) from exc

        issues = collect_issues(
            validate_file_path(file_path, must_exist=True),
            validate_password(password),
        )
        if issues:
            text = "\n".join(f"{issue.field}: {issue.message}" for issue in issues)
            self._dialog("Ошибки", text)
            raise ValueError(text)

        return file_path, output_path, decoy_message

    # ---------- Actions ----------
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
                progress_cb=lambda v: Clock.schedule_once(lambda *_: self._set_progress(v)),
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
                progress_cb=lambda v: Clock.schedule_once(lambda *_: self._set_progress(v)),
                completion_cb=self._on_operation_complete,
            )

        self._run_wizard(on_finish=_finish_wizard)

    def _on_operation_complete(self, error: str | None) -> None:
        def _update(*_):
            self.busy = False
            if error:
                self._set_status(f"Ошибка: {error}")
                self._dialog("Ошибка", error)
            else:
                self._set_status("Операция завершена")
                record_event("ui.operation.complete", details={"screen": "main"})
                Snackbar(text="Готово").open()
            self._set_progress(0)

        Clock.schedule_once(_update)

    def show_metadata(self) -> None:
        try:
            path = self.ids.file_path.text.strip()
            if not path:
                raise ValueError("Укажите путь к контейнеру.")
            metadata = verify_container(path)
            text = "\n".join(f"{k}: {v}" for k, v in metadata.items())
            self._dialog("Метаданные", text)
        except (IntegrityError, ValueError) as exc:
            self._dialog("Ошибка метаданных", str(exc))


class ZilantPrimeApp(MDApp):
    watchdog: EnvironmentWatchdog | None = None
    dev_override = DEV_OVERRIDE

    def build(self):
        # базовая тема и безопасность
        self.title = "Zilant Prime Mobile"
        self.theme_cls.primary_palette = "Blue"
        self.theme_cls.theme_style = "Dark"
        apply_secure_window(Window)
        enforce_pause_lock(self)
        self._register_recipes()

        # проверки среды
        issues = run_environment_checks()
        sm = Builder.load_string(KV)

        lock_screen: LockScreen = sm.get_screen("lock")
        main_screen: MainScreen = sm.get_screen("main")

        if issues:
            record_event(
                "security.environment",
                details={"issues": [{"severity": i.severity, "message": i.message} for i in issues]},
            )
            lock_screen.report_issues(issues)
            # в dev-режиме не инвалидируем сессию на старте
            if any(i.severity == "critical" for i in issues) and not self.dev_override:
                session_manager.invalidate("Обнаружены угрозы среды при запуске")

        def _lockdown_handler(found_issues: list[SecurityIssue]) -> None:
            session_manager.invalidate("Watchdog заблокировал сессию")
            main_screen.controller.cancel()
            main_screen.busy = False
            main_screen._set_status("Среда небезопасна. Сессия заблокирована.")
            sm.current = "lock"
            lock_screen.lockdown = True
            lock_screen.report_issues(found_issues)

        # watchdog оставляем, но без агрессии в dev-режиме
        self.watchdog = EnvironmentWatchdog(
            interval=10.0,
            scheduler=lambda fn: Clock.schedule_once(lambda *_: fn()),
            issue_handler=lock_screen.report_issues,
            lockdown_handler=(None if self.dev_override else _lockdown_handler),
        )
        self.watchdog.start()
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

    def on_stop(self) -> None:
        if self.watchdog:
            self.watchdog.stop()
        session_manager.clear()


if __name__ == "__main__":
    # Разрешения на Android (SAF/скриншоты блокируются флагом secure — это ок)
    try:
        from android.permissions import Permission, request_permissions
        request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])
    except Exception:
        pass

    ZilantPrimeApp().run()
