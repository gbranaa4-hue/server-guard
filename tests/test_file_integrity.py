"""FileIntegrityCollector must: baseline a genuinely new file on first
run (reporting changed=0.0, since there's nothing to diff against yet),
detect a REAL content modification on a subsequent run (not mocked --
an actual temp file is written, hashed, rewritten, and re-hashed),
report unchanged=0.0 across repeated runs with no modification, and
raise a _check_failed sentinel for a file that's missing/unreadable
without taking down any other manifest entry in the same tick."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collectors.file_integrity import FileIntegrityCollector


def _write_manifest(path, files):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"files": files}, f)


def test_collect_returns_empty_dict_when_manifest_missing():
    collector = FileIntegrityCollector(manifest_path="C:/definitely/does/not/exist.json")
    assert collector.collect() == {}


def test_first_run_baselines_and_reports_unchanged():
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "watched.txt")
        with open(target, "w", encoding="utf-8") as f:
            f.write("original content\n")

        manifest_path = os.path.join(d, "fim_manifest.json")
        _write_manifest(manifest_path, [{"name": "watched-file", "path": target}])

        collector = FileIntegrityCollector(manifest_path=manifest_path)
        values = collector.collect()

        assert values.get("watched-file_changed") == 0.0
        assert os.path.exists(collector.baseline_path)
        with open(collector.baseline_path, "r", encoding="utf-8") as f:
            baseline = json.load(f)
        assert "watched-file" in baseline
        assert "sha256" in baseline["watched-file"]


def test_unchanged_file_stays_zero_across_repeated_runs():
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "watched.txt")
        with open(target, "w", encoding="utf-8") as f:
            f.write("steady state\n")

        manifest_path = os.path.join(d, "fim_manifest.json")
        _write_manifest(manifest_path, [{"name": "watched-file", "path": target}])

        collector = FileIntegrityCollector(manifest_path=manifest_path)
        first = collector.collect()   # baselines
        second = collector.collect()  # real diff against persisted baseline
        third = collector.collect()   # another real diff, nothing changed

        assert first["watched-file_changed"] == 0.0
        assert second["watched-file_changed"] == 0.0
        assert third["watched-file_changed"] == 0.0


def test_real_content_modification_is_detected():
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "watched.txt")
        with open(target, "w", encoding="utf-8") as f:
            f.write("original content\n")

        manifest_path = os.path.join(d, "fim_manifest.json")
        _write_manifest(manifest_path, [{"name": "watched-file", "path": target}])

        collector = FileIntegrityCollector(manifest_path=manifest_path)
        baseline_run = collector.collect()
        assert baseline_run["watched-file_changed"] == 0.0

        # Real modification -- not mocked.
        with open(target, "w", encoding="utf-8") as f:
            f.write("TAMPERED content\n")

        changed_run = collector.collect()
        assert changed_run["watched-file_changed"] == 1.0

        # Stays flagged on a further run even with no further edits --
        # the baseline is not silently replaced by the changed hash.
        still_flagged_run = collector.collect()
        assert still_flagged_run["watched-file_changed"] == 1.0


def test_missing_file_reports_check_failed_and_isolates_other_entries():
    with tempfile.TemporaryDirectory() as d:
        present = os.path.join(d, "present.txt")
        with open(present, "w", encoding="utf-8") as f:
            f.write("present\n")
        missing = os.path.join(d, "does_not_exist.txt")

        manifest_path = os.path.join(d, "fim_manifest.json")
        _write_manifest(manifest_path, [
            {"name": "present-file", "path": present},
            {"name": "missing-file", "path": missing},
        ])

        collector = FileIntegrityCollector(manifest_path=manifest_path)
        values = collector.collect()

        assert values.get("present-file_changed") == 0.0
        assert values.get("missing-file_check_failed") == 1.0
        assert "missing-file_changed" not in values


def test_file_that_later_disappears_reports_check_failed():
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "watched.txt")
        with open(target, "w", encoding="utf-8") as f:
            f.write("here for now\n")

        manifest_path = os.path.join(d, "fim_manifest.json")
        _write_manifest(manifest_path, [{"name": "watched-file", "path": target}])

        collector = FileIntegrityCollector(manifest_path=manifest_path)
        baseline_run = collector.collect()
        assert baseline_run["watched-file_changed"] == 0.0

        os.remove(target)

        after_delete = collector.collect()
        assert after_delete.get("watched-file_check_failed") == 1.0
        assert "watched-file_changed" not in after_delete


def test_directory_path_reports_check_failed_not_a_crash():
    with tempfile.TemporaryDirectory() as d:
        watched_dir = os.path.join(d, "a_directory")
        os.makedirs(watched_dir)

        manifest_path = os.path.join(d, "fim_manifest.json")
        _write_manifest(manifest_path, [{"name": "some-dir", "path": watched_dir}])

        collector = FileIntegrityCollector(manifest_path=manifest_path)
        values = collector.collect()

        assert values.get("some-dir_check_failed") == 1.0


if __name__ == "__main__":
    test_collect_returns_empty_dict_when_manifest_missing()
    test_first_run_baselines_and_reports_unchanged()
    test_unchanged_file_stays_zero_across_repeated_runs()
    test_real_content_modification_is_detected()
    test_missing_file_reports_check_failed_and_isolates_other_entries()
    test_file_that_later_disappears_reports_check_failed()
    test_directory_path_reports_check_failed_not_a_crash()
    print("all tests passed")
