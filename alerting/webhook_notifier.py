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

from urllib.parse import urlsplit, urlunsplit

import requests


def _redact_url(url: str) -> str:
    """Real secret-leakage bug caught by testing a deliberately-failing
    webhook: requests' exception messages embed the FULL request URL
    (`404 Client Error: Not Found for url: https://hooks.slack.com/
    services/T00/B00/<real-token>`), so a webhook failure would have
    written the bearer-token-like URL straight into the plaintext
    rotating log file. Keeps only scheme+host (useful for "which
    notifier failed"), redacts the path/query where the actual secret
    lives."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "/[redacted]", "", ""))


class WebhookNotifierError(Exception):
    pass


class WebhookNotifier:
    name = "webhook"

    def __init__(self, url: str, style: str = "generic", timeout_s: float = 5.0):
        self.url = url
        self.style = style
        self.timeout_s = timeout_s

    def send(self, title: str, message: str, severity: str) -> None:
        try:
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
        except requests.RequestException as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            status_part = f"HTTP {status}" if status else type(exc).__name__
            raise WebhookNotifierError(
                f"{status_part} posting to {_redact_url(self.url)}"
            ) from None  # `from None` -- the original exception (with the real URL) must not surface via __cause__/traceback either
