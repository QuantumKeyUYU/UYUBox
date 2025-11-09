"""Multi-step wizards for secure operations."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List

from kivy.clock import Clock


@dataclass
class WizardStep:
    title: str
    on_enter: Callable[[], None]
    on_complete: Callable[[], None]


@dataclass
class WizardController:
    steps: List[WizardStep]
    on_finish: Callable[[], None]
    current_index: int = field(default=0, init=False)

    def start(self) -> None:
        if not self.steps:
            self.on_finish()
            return
        Clock.schedule_once(lambda *_: self._enter_step(0))

    def complete_current(self) -> None:
        step = self.steps[self.current_index]
        step.on_complete()
        next_index = self.current_index + 1
        if next_index >= len(self.steps):
            self.on_finish()
        else:
            self.current_index = next_index
            Clock.schedule_once(lambda *_: self._enter_step(next_index))

    def _enter_step(self, index: int) -> None:
        self.current_index = index
        self.steps[index].on_enter()
