"""SYNTHETIC DEMO workflow collector -- there is no real vet-clinic
patient-flow data available yet (same real gap as the software-version
manifest: the operator can't provide it right now). This exists purely
to prove the bottleneck-detection and forecast-report mechanisms
actually work end-to-end before any real data is connected, the same
way examples/software_versions.example.vet-hospital.json proves the
version-tracking shape without pretending to be real captures.

Modeled on a generic 4-stage patient visit (check-in -> exam -> lab ->
checkout), each stage tracked as a wait-time-in-minutes channel plus one
overall throughput channel. Deliberately engineered so exactly ONE stage
(lab) has a genuine, worsening trend while the others stay flat and
noisy -- so the bottleneck detector's correctness can actually be
checked against a known right answer, not just trusted on faith.

DO NOT register this in a real deployment -- swap in a real collector
reading the clinic's actual practice-management/scheduling system
instead. Gated behind guard.py's --demo-workflow flag (off by default)
specifically so fake data can never silently end up alongside real
health/security data in server_guard.db.
"""

from __future__ import annotations

import random
import time
from typing import Dict


class WorkflowDemoCollector:
    name = "wf"

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)
        self._start_time = time.time()

    def collect(self) -> Dict[str, float]:
        elapsed_min = (time.time() - self._start_time) / 60.0

        checkin = max(0.0, self._rng.gauss(4.0, 1.0))
        exam = max(0.0, self._rng.gauss(12.0, 2.0))
        checkout = max(0.0, self._rng.gauss(5.0, 1.0))
        # the engineered bottleneck: rises steadily over time, unlike the others
        lab = max(0.0, 8.0 + elapsed_min * 1.5 + self._rng.gauss(0.0, 1.5))

        throughput = max(0.0, self._rng.gauss(6.0, 1.0))  # patients/hour, informational only

        return {
            "checkin_wait_min": round(checkin, 2),
            "exam_wait_min": round(exam, 2),
            "lab_wait_min": round(lab, 2),
            "checkout_wait_min": round(checkout, 2),
            "throughput_per_hour": round(throughput, 2),
        }
