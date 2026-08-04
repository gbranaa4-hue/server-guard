"""Loads config/alerting.json into a wired-up NotifierRegistry.
Missing file or missing sections just mean fewer/no notifiers -- never a
crash, matching the same "gracefully do less" pattern as the collectors
that need optional external things (Npcap, a software-version manifest)."""

from __future__ import annotations

import json
import os
from typing import Optional

from .base import NotifierRegistry
from .webhook_notifier import WebhookNotifier
from .email_notifier import EmailNotifier


def load_notifiers(config_path: str) -> NotifierRegistry:
    registry = NotifierRegistry()
    if not os.path.exists(config_path):
        return registry

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    for webhook_cfg in config.get("webhooks", []):
        registry.register(WebhookNotifier(
            url=webhook_cfg["url"],
            style=webhook_cfg.get("style", "generic"),
            timeout_s=webhook_cfg.get("timeout_s", 5.0),
        ))

    email_cfg = config.get("email")
    if email_cfg:
        registry.register(EmailNotifier(
            smtp_host=email_cfg["smtp_host"],
            smtp_port=email_cfg["smtp_port"],
            username=email_cfg.get("username", ""),
            password=email_cfg.get("password", ""),
            from_addr=email_cfg["from_addr"],
            to_addrs=email_cfg["to_addrs"],
            use_tls=email_cfg.get("use_tls", True),
        ))

    return registry


def load_min_renotify_interval(config_path: str, default: float = 60.0) -> float:
    if not os.path.exists(config_path):
        return default
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)
    return config.get("min_renotify_interval_s", default)
