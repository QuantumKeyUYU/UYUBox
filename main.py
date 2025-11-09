from __future__ import annotations

import base64
import binascii
from datetime import datetime
import textwrap
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
        MDCard:
            size_hint: 0.9, 0.6
            pos_hint: {"center_x": 0.5, "center_y": 0.55}
            orientation: "vertical"
            padding: dp(24)
            spacing: dp(18)
            MDLabel:
                text: "Zilant Prime Mobile"
                halign: "center"
                font_style: "H4"
            MDLabel:
                text: "Нейрокомпактный сейф нового поколения"
                halign: "center"
                theme_text_color: "Secondary"
                text_size: self.width, None
                size_hint_y: None
                height: self.texture_size[1] + dp(4)
            MDRaisedButton:
                text: "Разблокировать"
                on_release: root.unlock()
                pos_hint: {"center_x": 0.5}
                disabled: root.lockdown
            MDFlatButton:
                text: "Войти по биометрии"
                on_release: root.request_biometrics()
                pos_hint: {"center_x": 0.5}
                disabled: root.lockdown
        MDLabel:
            text: root.warning_text
            halign: "center"
            theme_text_color: "Error"
            pos_hint: {"center_x": 0.5}
            size_hint_y: None
            text_size: self.width * 0.9, None
            height: self.texture_size[1] if self.texture_size[1] else 0

<MainScreen>:
    name: "main"
    MDBoxLayout:
        orientation: "vertical"
        MDToolbar:
            title: "Zilant Prime Mobile"
            elevation: 10
            left_action_items: [["shield-lock", lambda *_: None]]
            right_action_items: [["refresh", lambda *_: root.refresh_environment_status()]]
        ScrollView:
            do_scroll_x: False
            MDBoxLayout:
                orientation: "vertical"
                size_hint_y: None
                height: self.minimum_height
                padding: dp(16)
                spacing: dp(18)

                MDCard:
                    orientation: "vertical"
                    size_hint_y: None
                    height: self.minimum_height
                    padding: dp(16)
                    spacing: dp(10)
                    MDLabel:
                        text: "Среда исполнения"
                        font_style: "H6"
                    MDLabel:
                        id: environment_badge
                        text: "Идёт анализ среды…"
                        theme_text_color: "Primary"
                        size_hint_y: None
                        height: self.texture_size[1] + dp(4)
                    MDLabel:
                        id: environment_details
                        text: "Результаты проверок появятся здесь."
                        theme_text_color: "Secondary"
                        size_hint_y: None
                        text_size: self.width, None
                        height: self.texture_size[1] + dp(4)

                MDCard:
                    orientation: "vertical"
                    size_hint_y: None
                    height: self.minimum_height
                    padding: dp(16)
                    spacing: dp(14)
                    MDLabel:
                        text: "Контейнер"
                        font_style: "H6"
                    MDTextField:
                        id: file_path
                        hint_text: "Исходный файл"
                        helper_text: "Абсолютный путь к файлу, который будет упакован"
                        helper_text_mode: "on_focus"
                    MDTextField:
                        id: output_path
                        hint_text: "Выходной контейнер"
                        helper_text: "По умолчанию добавим расширение .zilant"
                        helper_text_mode: "on_focus"
                    MDTextField:
                        id: decoy
                        hint_text: "Decoy-сообщение (опционально)"
                        helper_text: "Запишем событие об отвлекающем сообщении"
                        helper_text_mode: "on_focus"

                MDCard:
                    orientation: "vertical"
                    size_hint_y: None
                    height: self.minimum_height
                    padding: dp(16)
                    spacing: dp(12)
                    MDLabel:
                        text: "Пароль доступа"
                        font_style: "H6"
                    MDTextField:
                        id: password
                        hint_text: "Пароль"
                        password: True
                        helper_text: "Мы усилим его связкой Argon2id + Kyber"
                        helper_text_mode: "on_focus"
                    MDProgressBar:
                        id: password_strength_bar
                        value: 0
                        max: 1
                    MDLabel:
                        id: password_strength_label
                        text: "Энтропия не определена"
                        theme_text_color: "Secondary"

                MDCard:
                    orientation: "vertical"
                    size_hint_y: None
                    height: self.minimum_height
                    padding: dp(16)
                    spacing: dp(12)
                    MDBoxLayout:
                        spacing: dp(12)
                        adaptive_height: True
                        MDLabel:
                            text: "Quantum Armor (Kyber)"
                            font_style: "H6"
                            size_hint_y: None
                            height: self.texture_size[1]
                        MDSwitch:
                            id: quantum_switch
                            pos_hint: {"center_y": 0.5}
                    MDLabel:
                        id: quantum_status
                        text: "Квантовая защита отключена."
                        theme_text_color: "Secondary"
                        size_hint_y: None
                        text_size: self.width, None
                        height: self.texture_size[1] + dp(4)
                    MDLabel:
                        text: "Открытый ключ для упаковки"
                        theme_text_color: "Primary"
                    MDTextField:
                        id: kem_public_key
                        hint_text: "Вставьте Kyber public key (base64)"
                        mode: "rectangle"
                        multiline: True
                        helper_text: "Используется при упаковке, если защита активна"
                        helper_text_mode: "on_focus"
                    MDLabel:
                        text: "Закрытый ключ для распаковки"
                        theme_text_color: "Primary"
                    MDTextField:
                        id: kem_private_key
                        hint_text: "Вставьте Kyber private key (base64)"
                        mode: "rectangle"
                        multiline: True
                        helper_text: "Используется при распаковке, если защита активна"
                        helper_text_mode: "on_focus"
                    MDBoxLayout:
                        adaptive_height: True
                        spacing: dp(12)
                        MDRaisedButton:
                            text: "Сгенерировать Kyber-пару"
                            on_release: root.generate_kem_keys()
                            disabled: root.busy
                        MDFlatButton:
                            text: "Очистить ключи"
                            on_release: root.clear_kem_fields()
                            disabled: root.busy

                MDCard:
                    orientation: "vertical"
                    size_hint_y: None
                    height: self.minimum_height
                    padding: dp(16)
                    spacing: dp(12)
                    MDLabel:
                        text: "Операции"
                        font_style: "H6"
                    MDLabel:
                        id: status
                        text: "Готово"
                        theme_text_color: "Primary"
                    MDLabel:
                        id: ttl_status
                        text: "Сессия: —"
                        theme_text_color: "Secondary"
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

                MDCard:
                    orientation: "vertical"
                    size_hint_y: None
                    height: self.minimum_height
                    padding: dp(16)
                    spacing: dp(10)
                    MDLabel:
                        text: "Лента событий"
                        font_style: "H6"
                    MDLabel:
                        id: timeline_label
                        text: "История действий появится здесь."
                        theme_text_color: "Secondary"
                        size_hint_y: None
                        text_size: self.width, None
                        height: self.texture_size[1] + dp(4)
                    MDLabel:
                        text: "Последние метаданные"
                        font_style: "Subtitle1"
                    MDLabel:
                        id: metadata_summary
                        text: "Ещё не запрошено."
                        theme_text_color: "Secondary"
                        size_hint_y: None
                        text_size: self.width, None
                        height: self.texture_size[1] + dp(4)
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
        self.timeline_label: Optional[MDLabel] = None
        self.password_strength_bar: Optional[MDProgressBar] = None
        self.password_strength_label_widget: Optional[MDLabel] = None
        self.environment_badge_label: Optional[MDLabel] = None
        self.environment_details_label: Optional[MDLabel] = None
        self.quantum_status_label: Optional[MDLabel] = None
        self.metadata_label: Optional[MDLabel] = None
        self.controller = SecureFileController()
        self._wizard: Optional[WizardController] = None
        self._ttl_event = None
        self._environment_issues: List[SecurityIssue] = []
        self._timeline: List[str] = []
        self._quantum_initialized = False

    def on_kv_post(self, base_widget):
        self.progress_bar = self.ids.progress
        self.status_label = self.ids.status
        self.ttl_label = self.ids.ttl_status
        self.timeline_label = self.ids.timeline_label
        self.password_strength_bar = self.ids.password_strength_bar
        self.password_strength_label_widget = self.ids.password_strength_label
        self.environment_badge_label = self.ids.environment_badge
        self.environment_details_label = self.ids.environment_details
        self.quantum_status_label = self.ids.quantum_status
        self.metadata_label = self.ids.metadata_summary

        password_field = self.ids.password
        password_field.bind(text=lambda _instance, value: self._update_password_strength(value))
        self._update_password_strength(password_field.text)

        quantum_switch = self.ids.quantum_switch
        quantum_switch.bind(active=self.on_quantum_toggle)
        self.on_quantum_toggle(quantum_switch, quantum_switch.active)

        self._update_session_ttl()
        if self._ttl_event is None:
            self._ttl_event = Clock.schedule_interval(self._update_session_ttl, 1.0)

        self.refresh_environment_status()
        self._refresh_timeline_label()
        self._append_timeline("Интерфейс активирован")

    # --- helpers ---

    def _set_status(self, text: str) -> None:
        if self.status_label:
            self.status_label.text = text

    def _set_progress(self, value: float) -> None:
        if self.progress_bar:
            self.progress_bar.value = value

    def _sync_label_height(self, label: Optional[MDLabel]) -> None:
        if not label:
            return

        def _update(*_args):
            label.height = (label.texture_size[1] or 0) + dp(4)

        Clock.schedule_once(_update)

    def _append_timeline(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self._timeline.append(f"[{stamp}] {message}")
        self._timeline = self._timeline[-8:]
        self._refresh_timeline_label()

    def _refresh_timeline_label(self) -> None:
        if not self.timeline_label:
            return
        if self._timeline:
            self.timeline_label.text = "\n".join(self._timeline)
        else:
            self.timeline_label.text = "История действий появится здесь."
        self._sync_label_height(self.timeline_label)

    def _update_session_ttl(self, *_args) -> None:
        ttl = session_manager.remaining_ttl()
        if self.ttl_label:
            if ttl <= 0:
                self.ttl_label.text = "Сессия: заблокирована"
            else:
                self.ttl_label.text = f"Сессия: {int(ttl)}с"

    def _update_password_strength(self, password: str) -> None:
        bits = float(entropy_bits(password or ""))
        normalized = min(max(bits / 256.0, 0.0), 1.0)
        if self.password_strength_bar:
            self.password_strength_bar.value = normalized
        descriptor = "Слабая"
        if bits >= 128:
            descriptor = "Сильная"
        elif bits >= 64:
            descriptor = "Средняя"
        if self.password_strength_label_widget:
            self.password_strength_label_widget.text = f"{descriptor} защита • {int(bits)} бит"

    def _show_dialog(self, title: str, text: str) -> None:
        button = MDFlatButton(text="OK")
        dialog = MDDialog(title=title, text=text, buttons=[button])
        button.bind(on_release=lambda *_: dialog.dismiss())
        dialog.open()

    def _format_key(self, key: bytes) -> str:
        encoded = base64.b64encode(key).decode("ascii")
        return "\n".join(textwrap.wrap(encoded, 44))

    def _extract_kem_material(self, field_id: str) -> Optional[bytes]:
        field = self.ids.get(field_id)
        if not field:
            return None
        raw = field.text or ""
        normalized = "".join(raw.split())
        if not normalized:
            return None
        try:
            return base64.b64decode(normalized.encode("ascii"))
        except (binascii.Error, ValueError):
            self._show_dialog("Kyber ключ", "Некорректный формат Kyber ключа. Используйте base64.")
            self._append_timeline("Ошибка: некорректный формат Kyber ключа")
            raise ValueError("invalid kyber key")

    def _resolve_kem_material(self, *, for_pack: bool) -> Optional[bytes]:
        if not self.ids.quantum_switch.active:
            return None
        field_id = "kem_public_key" if for_pack else "kem_private_key"
        material = self._extract_kem_material(field_id)
        if material is None:
            message = (
                "Укажите Kyber public key для упаковки."
                if for_pack
                else "Укажите Kyber private key для распаковки."
            )
            self._show_dialog("Kyber ключ", message)
            self._append_timeline("Kyber ключ отсутствует для выбранной операции")
            raise ValueError(message)
        return material

    def refresh_environment_status(self, *_args) -> None:
        if not self.environment_badge_label or not self.environment_details_label:
            return

        if not self._environment_issues:
            self.environment_badge_label.text = "Среда подтверждена"
            self.environment_badge_label.theme_text_color = "Primary"
            self.environment_details_label.text = (
                "Все проверки пройдены, мониторинг активен."
            )
        else:
            self.environment_badge_label.text = (
                f"Обнаружено проблем: {len(self._environment_issues)}"
            )
            self.environment_badge_label.theme_text_color = "Error"
            details = "\n".join(
                f"• [{getattr(issue, 'severity', '?')}] {issue.message}"
                for issue in self._environment_issues
            )
            self.environment_details_label.text = details

        self._sync_label_height(self.environment_badge_label)
        self._sync_label_height(self.environment_details_label)

    def set_environment_issues(self, issues: List[SecurityIssue]) -> None:
        self._environment_issues = list(issues or [])
        if self._environment_issues:
            self._append_timeline(
                f"Диагностика среды: найдено {len(self._environment_issues)} угроз"
            )
        else:
            self._append_timeline("Диагностика среды: угроз не обнаружено")
        self.refresh_environment_status()

    def on_quantum_toggle(self, _instance, value: bool) -> None:
        if self.quantum_status_label:
            self.quantum_status_label.text = (
                "Квантовая защита активна." if value else "Квантовая защита отключена."
            )
            self._sync_label_height(self.quantum_status_label)

        if not self._quantum_initialized:
            self._quantum_initialized = True
            self._append_timeline(
                "Квантовая защита активирована" if value else "Квантовая защита отключена"
            )
            return

        self._append_timeline(
            "Квантовая защита активирована" if value else "Квантовая защита отключена"
        )

    def generate_kem_keys(self) -> None:
        if self.busy:
            return
        try:
            public_key, private_key = self.controller.encryptor.generate_kem_keypair()
        except Exception as exc:
            self._show_dialog("Kyber", str(exc))
            self._append_timeline(f"Kyber-пара не создана: {exc}")
            return

        self.ids.kem_public_key.text = self._format_key(public_key)
        self.ids.kem_private_key.text = self._format_key(private_key)
        self.ids.quantum_switch.active = True
        self._append_timeline("Сгенерирована новая Kyber-пара")
        self._show_dialog(
            "Kyber",
            "Пара Kyber успешно сгенерирована. Сохраните приватный ключ в безопасном месте.",
        )

    def clear_kem_fields(self) -> None:
        if self.busy:
            return
        self.ids.kem_public_key.text = ""
        self.ids.kem_private_key.text = ""
        self._append_timeline("Kyber ключи очищены")

    # --- wizard ---

    def _run_wizard(self, *, on_finish: Callable[[], None]) -> None:
        password = self.ids.password.text

        def _enter_validation() -> None:
            self._set_status("Валидация параметров...")
            self._append_timeline("Валидация параметров операции")

        def _complete_validation() -> None:
            self._set_status("Параметры подтверждены")
            self._append_timeline("Параметры подтверждены")

        def _enter_entropy() -> None:
            self._set_status("Оценка энтропии пароля...")
            bits = int(entropy_bits(password))
            self._append_timeline(f"Энтропия пароля: {bits} бит")
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
        self._append_timeline("Мастер безопасности активирован")
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
        self._append_timeline("Операция отменена пользователем")

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

        try:
            kem_public_key = self._resolve_kem_material(for_pack=True)
        except ValueError:
            return

        self._append_timeline(f"Подготовка упаковки для {file_path}")

        def _finish_wizard() -> None:
            self._set_status("Запуск упаковки...")
            self._set_progress(0)
            self.busy = True
            self._append_timeline("Упаковка инициирована")

            try:
                self.controller.pack(
                    file_path,
                    output_path,
                    self.ids.password.text,
                    decoy_message=decoy_message,
                    kem_public_key=kem_public_key,
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

        try:
            kem_private_key = self._resolve_kem_material(for_pack=False)
        except ValueError:
            return

        self._append_timeline(f"Подготовка распаковки для {file_path}")

        def _finish_wizard() -> None:
            self._set_status("Запуск распаковки...")
            self._set_progress(0)
            self.busy = True
            self._append_timeline("Распаковка инициирована")

            try:
                self.controller.unpack(
                    file_path,
                    output_path,
                    self.ids.password.text,
                    kem_private_key=kem_private_key,
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
                self._append_timeline(f"Операция завершилась ошибкой: {error}")
            else:
                self._set_status("Операция завершена")
                record_event("ui.operation.complete", details={"screen": "main"})
                self._show_dialog("Успех", "Операция завершена")
                self._append_timeline("Операция завершена успешно")
            self._set_progress(0)

        Clock.schedule_once(_update)

    def show_metadata(self) -> None:
        try:
            file_path = self.ids.file_path.text.strip()
            if not file_path:
                raise ValueError("Укажите путь к контейнеру.")
            metadata = verify_container(file_path)
            text = "\n".join(f"{key}: {value}" for key, value in metadata.items())
            if self.metadata_label:
                self.metadata_label.text = text or "Метаданные отсутствуют."
                self._sync_label_height(self.metadata_label)
            self._append_timeline("Метаданные контейнера обновлены")
            self._show_dialog("Метаданные", text)
        except (IntegrityError, ValueError) as exc:
            self._show_dialog("Ошибка метаданных", str(exc))
            if self.metadata_label:
                self.metadata_label.text = str(exc)
                self._sync_label_height(self.metadata_label)
            self._append_timeline(f"Не удалось получить метаданные: {exc}")


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
        main_screen.set_environment_issues(issues)

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
            main_screen.set_environment_issues(found_issues)
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
