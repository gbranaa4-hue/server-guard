"""Generic webhook notifier -- one HTTP POST, three real payload shapes
covering the actual services people reach for: Slack/Discord/Mattermost
incoming webhooks (all accept the same `{"text": ...}` shape), ntfy.sh
(plain-text body + headers, zero signup required -- the real thing this
was verified against), and a generic JSON shape for a custom endpoint.

No credentials are ever handled by this process beyond a webhook URL the
operator supplies in their own local config file -- see
config/alerting.example.json. That file is never committed with a real
URL in it (config/alerting.json is gitignored) since a webhook URL is
itself bearer-token-like: anyone with it can post to the channel.
"""

from __future__ import annotations

import requests


class WebhookNotifier:
    name = "webhook"

    def __init__(self, url: str, style: str = "generic", timeout_s: float = 5.0):
        self.url = url
        self.style = style
        self.timeout_s = timeout_s

    def send(self, title: str, message: str, severity: str) -> None:
        if self.style == "slack":
            payload = {"text": f"*[{severity.upper()}] {title}*\n{message}"}
            resp = requests.post(self.url, json=payload, timeout=self.timeout_s)
        elif self.style == "ntfy":
            headers = {"Title": title, "Priority": "urgent" if severity == "critical" else "default"}
            resp = requests.post(self.url, data=message.encode("utf-8"), headers=headers,
                                  timeout=self.timeout_s)
        else:
            payload = {"title": title, "message": message, "severity": severity}
            resp = requests.post(self.url, json=payload, timeout=self.timeout_s)
        resp.raise_for_status()
