"""Workflow engine prototype for secure data pipelines."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Sequence


@dataclass
class WorkflowStep:
    title: str
    description: str
    action: Callable[[], str]

    def execute(self) -> str:
        return self.action()


@dataclass
class Workflow:
    name: str
    steps: Sequence[WorkflowStep] = field(default_factory=list)

    def run(self) -> List[str]:
        return [step.execute() for step in self.steps]


def build_default_workflows() -> List[Workflow]:
    """Return canned workflows used by the UI builder canvas."""

    def scan_action() -> str:
        return "Сканирование каталога завершено — угроз не выявлено"

    def classify_action() -> str:
        return "Файлы классифицированы: 2 критичных, 5 конфиденциальных"

    def encrypt_action() -> str:
        return "Контейнеры .zilx сформированы с двойным шифрованием"

    def deliver_action() -> str:
        return "Secure Gateway уведомил 3 получателей через WebRTC"

    return [
        Workflow(
            name="Полный цикл защиты",
            steps=[
                WorkflowStep("Сканирование", "Поиск чувствительных данных", scan_action),
                WorkflowStep("Классификация", "AI-анализ для выбора политики", classify_action),
                WorkflowStep("Шифрование", "Адаптивный профиль Argon2id", encrypt_action),
                WorkflowStep("Доставка", "Zero-trust передача", deliver_action),
            ],
        ),
        Workflow(
            name="Экспорт доказательств",
            steps=[
                WorkflowStep(
                    "Формирование доказательства", "Zero-knowledge доказательство неизменности", lambda: "ZKP сформировано",
                ),
                WorkflowStep(
                    "Публикация", "Отправка в частный реестр для аудита", lambda: "Запись в Ledger обновлена",
                ),
            ],
        ),
    ]
