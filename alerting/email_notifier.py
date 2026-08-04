"""SMTP email notifier -- stdlib only, no new dependency. SMTP
credentials live in the operator's own local config/alerting.json
(gitignored), read and used only to authenticate to THEIR OWN mail
server. This process never sees or stores credentials beyond what's in
that local file."""

from __future__ import annotations

import smtplib
from email.mime.text import MIMEText


class EmailNotifier:
    name = "email"

    def __init__(self, smtp_host: str, smtp_port: int, username: str, password: str,
                 from_addr: str, to_addrs: list, use_tls: bool = True):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.use_tls = use_tls

    def send(self, title: str, message: str, severity: str) -> None:
        msg = MIMEText(message)
        msg["Subject"] = f"[server-guard {severity.upper()}] {title}"
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)

        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
            if self.use_tls:
                server.starttls()
            if self.username:
                server.login(self.username, self.password)
            server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
