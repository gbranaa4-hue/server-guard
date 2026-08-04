"""Regression test for a real secret-leakage bug: requests' exception
messages embed the full request URL, so a failing webhook (Slack,
Discord, ntfy) would have written its bearer-token-like URL straight
into the plaintext rotating log file. Caught by deliberately triggering
a real failed POST and reading the actual exception string, not by
inspection."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from alerting.webhook_notifier import WebhookNotifier, WebhookNotifierError, _redact_url


def test_redact_url_strips_path_and_query():
    secret_url = "https://hooks.slack.com/services/T00000000/B00000000/FAKESECRETTOKEN1234567890"
    redacted = _redact_url(secret_url)
    assert "FAKESECRETTOKEN1234567890" not in redacted
    assert redacted == "https://hooks.slack.com/[redacted]"


def test_real_failed_post_does_not_leak_the_url_in_the_exception():
    """Live test, not a mock: a real request to a real host that returns
    404, confirming the ACTUAL requests exception (which does contain the
    real URL) never surfaces past this notifier."""
    secret_token = "FAKESECRETTOKEN1234567890"
    n = WebhookNotifier(
        url=f"https://httpbin.org/status/404?token={secret_token}",
        style="generic", timeout_s=8,
    )
    try:
        n.send("test", "test message", "critical")
        assert False, "expected a WebhookNotifierError"
    except WebhookNotifierError as exc:
        assert secret_token not in str(exc)
    except Exception as exc:
        # network unavailable in this environment -- not what this test is checking
        if "NameResolutionError" in type(exc).__name__ or "ConnectionError" in type(exc).__name__:
            print("skipped: no network access in this environment")
        else:
            raise


if __name__ == "__main__":
    test_redact_url_strips_path_and_query()
    test_real_failed_post_does_not_leak_the_url_in_the_exception()
    print("all tests passed")
