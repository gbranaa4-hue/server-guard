"""BackupVerificationCollector must correctly report real elapsed hours
and real file size for a fresh backup file, correctly flag a genuinely
stale one, isolate a missing/unreadable target directory from a good
one, and report the disclosed NO_MATCHING_BACKUP_HOURS value when a
directory is real but nothing matches the glob yet -- verified against
REAL files on a real temp filesystem with real mtimes set via
os.utime(), not mocked."""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collectors.backup_verification import BackupVerificationCollector, NO_MATCHING_BACKUP_HOURS


def _write_manifest(path, targets):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"targets": targets}, f)


def test_fresh_backup_reports_small_age_and_real_size():
    with tempfile.TemporaryDirectory() as d:
        backup_dir = os.path.join(d, "fresh")
        os.makedirs(backup_dir)
        file_path = os.path.join(backup_dir, "dump.bak")
        payload = b"x" * 12345
        with open(file_path, "wb") as f:
            f.write(payload)
        # mtime is "now" by default -- no os.utime() needed for the fresh case

        manifest_path = os.path.join(d, "backup_targets.json")
        _write_manifest(manifest_path, [
            {"name": "fresh-target", "directory": backup_dir, "glob": "*.bak",
             "expected_max_age_hours": 30, "min_expected_size_bytes": 100}
        ])

        collector = BackupVerificationCollector(manifest_path=manifest_path)
        values = collector.collect()

        assert "fresh-target_check_failed" not in values
        assert values["fresh-target_hours_since_last_backup"] < 0.01
        assert values["fresh-target_last_backup_size_bytes"] == float(len(payload))


def test_stale_backup_reports_real_elapsed_hours():
    with tempfile.TemporaryDirectory() as d:
        backup_dir = os.path.join(d, "stale")
        os.makedirs(backup_dir)
        file_path = os.path.join(backup_dir, "old.bak")
        with open(file_path, "wb") as f:
            f.write(b"data")

        # Real stale mtime: 100 hours in the past, set directly via os.utime
        # (same technique cert_expiry's own tests use for reproducible time
        # values without waiting real wall-clock time).
        stale_time = time.time() - (100 * 3600)
        os.utime(file_path, (stale_time, stale_time))

        manifest_path = os.path.join(d, "backup_targets.json")
        _write_manifest(manifest_path, [
            {"name": "stale-target", "directory": backup_dir, "glob": "*.bak",
             "expected_max_age_hours": 30, "min_expected_size_bytes": 1}
        ])

        collector = BackupVerificationCollector(manifest_path=manifest_path)
        values = collector.collect()

        assert 99.9 <= values["stale-target_hours_since_last_backup"] <= 100.1
        assert values["stale-target_last_backup_size_bytes"] == 4.0


def test_missing_directory_sets_check_failed():
    with tempfile.TemporaryDirectory() as d:
        manifest_path = os.path.join(d, "backup_targets.json")
        _write_manifest(manifest_path, [
            {"name": "missing-target", "directory": os.path.join(d, "does_not_exist"),
             "glob": "*.bak", "expected_max_age_hours": 30, "min_expected_size_bytes": 1}
        ])

        collector = BackupVerificationCollector(manifest_path=manifest_path)
        values = collector.collect()

        assert values.get("missing-target_check_failed") == 1.0
        assert "missing-target_hours_since_last_backup" not in values
        assert "missing-target_last_backup_size_bytes" not in values


def test_real_directory_with_no_matching_files_reports_the_disclosed_sentinel():
    with tempfile.TemporaryDirectory() as d:
        backup_dir = os.path.join(d, "empty")
        os.makedirs(backup_dir)
        # Directory is real and readable, but nothing matches the glob --
        # e.g. this target was wired up before its first backup ever ran.

        manifest_path = os.path.join(d, "backup_targets.json")
        _write_manifest(manifest_path, [
            {"name": "never-run-target", "directory": backup_dir, "glob": "*.bak",
             "expected_max_age_hours": 30, "min_expected_size_bytes": 1}
        ])

        collector = BackupVerificationCollector(manifest_path=manifest_path)
        values = collector.collect()

        assert values["never-run-target_hours_since_last_backup"] == NO_MATCHING_BACKUP_HOURS
        assert values["never-run-target_last_backup_size_bytes"] == 0.0
        assert "never-run-target_check_failed" not in values


def test_collect_isolates_a_bad_target_from_a_good_one():
    with tempfile.TemporaryDirectory() as d:
        good_dir = os.path.join(d, "good")
        os.makedirs(good_dir)
        with open(os.path.join(good_dir, "db.bak"), "wb") as f:
            f.write(b"real backup contents")

        manifest_path = os.path.join(d, "backup_targets.json")
        _write_manifest(manifest_path, [
            {"name": "missing-one", "directory": os.path.join(d, "nope"), "glob": "*.bak",
             "expected_max_age_hours": 30, "min_expected_size_bytes": 1},
            {"name": "good-one", "directory": good_dir, "glob": "*.bak",
             "expected_max_age_hours": 30, "min_expected_size_bytes": 1},
        ])

        collector = BackupVerificationCollector(manifest_path=manifest_path)
        values = collector.collect()

        assert values.get("missing-one_check_failed") == 1.0
        assert values["good-one_hours_since_last_backup"] < 0.01
        assert values["good-one_last_backup_size_bytes"] == float(len(b"real backup contents"))


def test_collect_returns_empty_dict_when_manifest_missing():
    collector = BackupVerificationCollector(manifest_path="C:/definitely/does/not/exist.json")
    assert collector.collect() == {}


def test_glob_only_matches_files_not_directories():
    """A subdirectory that happens to match the glob pattern (some backup
    tools create an "old.bak" rotation folder) must not be picked up as
    if it were a backup file."""
    with tempfile.TemporaryDirectory() as d:
        backup_dir = os.path.join(d, "mixed")
        os.makedirs(backup_dir)
        os.makedirs(os.path.join(backup_dir, "rotated.bak"))  # a directory, not a file
        real_file = os.path.join(backup_dir, "real.bak")
        with open(real_file, "wb") as f:
            f.write(b"actual backup")

        manifest_path = os.path.join(d, "backup_targets.json")
        _write_manifest(manifest_path, [
            {"name": "mixed-target", "directory": backup_dir, "glob": "*.bak",
             "expected_max_age_hours": 30, "min_expected_size_bytes": 1}
        ])

        collector = BackupVerificationCollector(manifest_path=manifest_path)
        values = collector.collect()

        assert values["mixed-target_last_backup_size_bytes"] == float(len(b"actual backup"))


if __name__ == "__main__":
    test_fresh_backup_reports_small_age_and_real_size()
    test_stale_backup_reports_real_elapsed_hours()
    test_missing_directory_sets_check_failed()
    test_real_directory_with_no_matching_files_reports_the_disclosed_sentinel()
    test_collect_isolates_a_bad_target_from_a_good_one()
    test_collect_returns_empty_dict_when_manifest_missing()
    test_glob_only_matches_files_not_directories()
    print("all tests passed")
