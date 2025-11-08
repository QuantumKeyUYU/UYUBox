from __future__ import annotations

from pathlib import Path
from typing import Optional

from kivy.properties import ObjectProperty, StringProperty
from kivymd.uix.screen import MDScreen

from app.services.audit import audit_ledger
from app.services.crypto_manager import CryptoManager, CryptoReport, SecurityTier, crypto_manager
from app.services.environment import DeviceStatus, probe_device


class HomeScreen(MDScreen):
    file_path = StringProperty("")
    message = StringProperty("Выберите файл и задайте действие")
    device_status: DeviceStatus = ObjectProperty(None)
    crypto: CryptoManager = crypto_manager

    def on_pre_enter(self, *args) -> None:
        super().on_pre_enter(*args)
        self.device_status = probe_device()
        tier = self.crypto.analyze_device_profile(
            battery_level=self.device_status.battery_level,
            temperature_c=self.device_status.temperature_c,
        )
        self.ids.security_tier_label.text = f"Рекомендованный профиль: {tier.value}"
        self.ids.environment_label.text = (
            f"Температура: {self.device_status.temperature_c}°C | "
            f"Батарея: {self.device_status.battery_level}% | "
            f"Root: {'да' if self.device_status.rooted else 'нет'} | "
            f"Эмулятор: {'да' if self.device_status.emulator else 'нет'}"
        )

    def _require_path(self) -> Optional[str]:
        if not self.file_path:
            self.message = "Путь к файлу не указан"
            return None
        return self.file_path

    def choose_file(self, path: str) -> None:
        self.file_path = path
        self.message = f"Выбран файл: {Path(path).name}"

    def _update_status(self, report: CryptoReport, audit_action: str) -> None:
        self.message = report.message
        if report.ok:
            audit_ledger.record("user", audit_action, self.file_path or "n/a")
        if report.metadata:
            meta_lines = [f"{key}: {value}" for key, value in report.metadata.items()]
            self.ids.metadata_label.text = "\n".join(meta_lines)

    def pack(self, password: str, output_name: str, tier: str) -> None:
        source = self._require_path()
        if not source:
            return
        try:
            profile = SecurityTier(tier)
        except ValueError:
            self.message = "Неизвестный профиль безопасности"
            return
        report = self.crypto.pack(source, password, output_name, profile)
        self._update_status(report, "pack")

    def unpack(self, password: str, output_name: str) -> None:
        source = self._require_path()
        if not source:
            return
        report = self.crypto.unpack(source, password, output_name)
        self._update_status(report, "unpack")

    def read_metadata(self) -> None:
        source = self._require_path()
        if not source:
            return
        report = self.crypto.metadata(source)
        self._update_status(report, "metadata")
