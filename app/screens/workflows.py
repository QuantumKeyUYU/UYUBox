from __future__ import annotations

from kivy.properties import ObjectProperty, StringProperty
from kivymd.uix.list import MDList
from kivymd.uix.screen import MDScreen

from app.services.workflows import Workflow, build_default_workflows


class WorkflowsScreen(MDScreen):
    workflows = ObjectProperty([])
    execution_log = ObjectProperty([])
    selected_workflow = StringProperty("")

    def on_pre_enter(self, *args) -> None:
        super().on_pre_enter(*args)
        if not self.workflows:
            self.workflows = build_default_workflows()
            if self.workflows:
                self.selected_workflow = self.workflows[0].name
        self._render_workflow_list()

    def _render_workflow_list(self) -> None:
        container: MDList = self.ids.workflow_list
        container.clear_widgets()
        for wf in self.workflows:
            container.add_widget(self._build_workflow_tile(wf))

    def _build_workflow_tile(self, workflow: Workflow):
        from kivymd.uix.list import OneLineListItem

        def _select_item(_: OneLineListItem) -> None:
            self.selected_workflow = workflow.name
            self.ids.workflow_summary.text = "\n".join(
                f"• {step.title} — {step.description}" for step in workflow.steps
            )

        item = OneLineListItem(text=workflow.name, on_release=_select_item)
        return item

    def execute(self) -> None:
        workflow = next((wf for wf in self.workflows if wf.name == self.selected_workflow), None)
        if not workflow:
            self.execution_log = ["Выберите сценарий"]
            return
        self.execution_log = workflow.run()
        self.ids.execution_output.text = "\n".join(self.execution_log)
