"""Composable offline workflows for secure automation."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List

from audit.logger import record_event


@dataclass
class Step:
    name: str
    action: Callable[[], None]


@dataclass
class Recipe:
    name: str
    steps: List[Step] = field(default_factory=list)

    def run(self) -> None:
        record_event("recipe.start", details={"name": self.name})
        for step in self.steps:
            record_event("recipe.step", details={"recipe": self.name, "step": step.name})
            step.action()
        record_event("recipe.done", details={"name": self.name})


class RecipeRegistry:
    def __init__(self) -> None:
        self._recipes: Dict[str, Recipe] = {}

    def register(self, recipe: Recipe) -> None:
        self._recipes[recipe.name] = recipe

    def get(self, name: str) -> Recipe:
        return self._recipes[name]

    def all(self) -> List[Recipe]:
        return list(self._recipes.values())


registry = RecipeRegistry()
