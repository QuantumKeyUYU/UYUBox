from __future__ import annotations

from kivy.properties import ObjectProperty, StringProperty
from kivymd.uix.list import MDList
from kivymd.uix.screen import MDScreen

from app.services.audit import audit_ledger
from app.services.secure_share import ShareSession, secure_share_gateway


class SecureShareScreen(MDScreen):
    sessions = ObjectProperty([])
    status_message = StringProperty("")

    def on_pre_enter(self, *args) -> None:
        super().on_pre_enter(*args)
        self.refresh()

    def refresh(self) -> None:
        self.sessions = secure_share_gateway.all_sessions()
        container: MDList = self.ids.sessions_list
        container.clear_widgets()
        for session in self.sessions:
            container.add_widget(self._build_session_row(session))

    def _build_session_row(self, session: ShareSession):
        from kivymd.uix.list import TwoLineListItem

        return TwoLineListItem(
            text=f"Сессия {session.session_id[:6]}",
            secondary_text=f"{session.pqc_suite} — участников: {len(session.participants)} (статус: {session.status})",
        )

    def create_session(self, owner: str, pqc_suite: str) -> None:
        session = secure_share_gateway.create_session(owner, pqc_suite)
        audit_ledger.record(owner or "anon", "create_session", session.session_id)
        self.status_message = f"Создана сессия {session.session_id}"
        self.refresh()

    def join_session(self, session_id: str, participant: str) -> None:
        try:
            session = secure_share_gateway.join(session_id, participant)
        except KeyError:
            self.status_message = "Сессия не найдена"
            return
        audit_ledger.record(participant or "guest", "join_session", session_id)
        self.status_message = f"{participant} подключился к сессии"
        self.refresh()
