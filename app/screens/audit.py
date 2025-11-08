from __future__ import annotations

from kivymd.uix.list import MDList
from kivymd.uix.screen import MDScreen

from app.services.audit import audit_ledger


class AuditScreen(MDScreen):
    def on_pre_enter(self, *args) -> None:
        super().on_pre_enter(*args)
        self.refresh()

    def refresh(self) -> None:
        events = audit_ledger.tail()
        container: MDList = self.ids.audit_list
        container.clear_widgets()
        for event in events:
            container.add_widget(self._build_row(event))

    def _build_row(self, event):
        from kivymd.uix.list import ThreeLineListItem

        return ThreeLineListItem(
            text=f"{event.actor} → {event.action}",
            secondary_text=event.timestamp.isoformat(timespec="seconds"),
            tertiary_text=f"hash: {event.digest[:16]}…",
        )
