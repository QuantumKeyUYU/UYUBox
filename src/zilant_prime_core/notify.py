from __future__ import annotations

import os
import requests

__all__ = ["Notifier"]


class Notifier:
    def __init__(self) -> None:
        self.slack_url = os.getenv("SLACK_WEBHOOK_URL")
        self.tg_token = os.getenv("TELEGRAM_TOKEN")
        self.tg_chat = os.getenv("TELEGRAM_CHAT_ID")

    def notify(self, text: str) -> None:
        if self.slack_url:
            try:
                requests.post(self.slack_url, json={"text": text}, timeout=5)
            except Exception:
                pass
        if self.tg_token and self.tg_chat:
            url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
            try:
                requests.post(url, data={"chat_id": self.tg_chat, "text": text}, timeout=5)
            except Exception:
                pass
