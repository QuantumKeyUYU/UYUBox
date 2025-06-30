# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

from zilant_prime_core.notify import Notifier


class Dummy:
    def __init__(self):
        self.sent = []

    def post(self, url, json=None, data=None, timeout=None):
        self.sent.append(url)

        class Resp:
            status_code = 200

        return Resp()


def test_notify_slack(monkeypatch):
    dummy = Dummy()
    monkeypatch.setattr("requests.post", dummy.post)
    n = Notifier()
    n.slack_url = "http://example.com"
    n.notify("oops")
    assert dummy.sent


def test_notify_telegram_and_errors(monkeypatch):
    sent = []

    def fake_post(url, json=None, data=None, timeout=None):
        sent.append(url)
        raise Exception("fail")

    monkeypatch.setattr("requests.post", fake_post)
    n = Notifier()
    n.slack_url = "http://slack"
    n.tg_token = "t"
    n.tg_chat = "c"
    n.notify("hi")
    assert "http://slack" in sent
    assert any("telegram" in u for u in sent)
