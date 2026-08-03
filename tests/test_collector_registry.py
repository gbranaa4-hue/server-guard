"""A flaky collector (network blip, remote server rebooting) must not take
down the whole tick -- its channels are just missing for that reading,
and the failure shows up in last_errors instead of vanishing silently."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collectors.base import CollectorRegistry


class GoodCollector:
    name = "good"

    def collect(self):
        return {"value": 42.0}


class BadCollector:
    name = "bad"

    def collect(self):
        raise RuntimeError("simulated unreachable server")


def test_merges_multiple_collectors():
    registry = CollectorRegistry()
    registry.register(GoodCollector())
    values = registry.collect_all()
    assert values == {"good.value": 42.0}


def test_failing_collector_does_not_break_the_tick():
    registry = CollectorRegistry()
    registry.register(GoodCollector())
    registry.register(BadCollector())
    values = registry.collect_all()
    assert values == {"good.value": 42.0}
    assert len(registry.last_errors) == 1
    assert registry.last_errors[0].collector_name == "bad"
    assert "simulated unreachable server" in registry.last_errors[0].error


if __name__ == "__main__":
    test_merges_multiple_collectors()
    test_failing_collector_does_not_break_the_tick()
    print("all tests passed")
