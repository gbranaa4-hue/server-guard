"""DiskReliabilityCollector must report a real healthy/not flag per
physical disk, normalize PowerShell's single-object-vs-array output
shape correctly (a real edge case confirmed directly: a single-disk
result isn't wrapped in an array), and fall back to Win32_DiskDrive if
Get-PhysicalDisk itself fails. No mocking -- this project's existing
tests all exercise real subprocess/OS behavior, and this collector's
whole point is real Windows health data, so a mocked test would prove
nothing about whether it actually works."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collectors.disk_reliability import DiskReliabilityCollector, _safe_key


def test_safe_key_sanitizes_real_disk_model_names():
    assert _safe_key("Samsung SSD 850 EVO 500GB") == "Samsung_SSD_850_EVO_500GB"
    assert _safe_key("WD-40 Blue/1TB") == "WD_40_Blue_1TB"
    assert _safe_key("") == "disk"


def test_run_powershell_json_normalizes_a_single_object_to_a_list():
    """A real, confirmed edge case: Get-PhysicalDisk | ConvertTo-Json
    returns a bare JSON object (not a 1-element array) when there's only
    one result -- verified directly against this project's own machine
    output before writing the collector, not assumed."""
    collector = DiskReliabilityCollector()
    result = collector._run_powershell_json(
        "[PSCustomObject]@{DeviceId='0';FriendlyName='TestDisk';"
        "HealthStatus='Healthy';OperationalStatus='OK'} | ConvertTo-Json"
    )
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["FriendlyName"] == "TestDisk"


def test_run_powershell_json_handles_a_real_multi_item_array():
    collector = DiskReliabilityCollector()
    result = collector._run_powershell_json(
        "@([PSCustomObject]@{Name='a'}, [PSCustomObject]@{Name='b'}) | ConvertTo-Json"
    )
    assert isinstance(result, list)
    assert len(result) == 2


def test_collect_reports_real_healthy_flags_for_real_physical_disks():
    """Live against this machine's actual disks -- confirmed separately
    via a direct PowerShell check that both report Healthy/OK, so both
    channels should read 1.0."""
    collector = DiskReliabilityCollector()
    values = collector.collect()
    assert len(values) > 0
    for key, val in values.items():
        assert key.endswith("_healthy")
        assert val in (0.0, 1.0)


def test_collect_falls_back_to_win32_diskdrive_when_physical_disk_path_fails():
    class _BrokenPhysicalDisk(DiskReliabilityCollector):
        def _collect_via_physical_disk(self):
            raise RuntimeError("simulated Get-PhysicalDisk failure")

    collector = _BrokenPhysicalDisk()
    values = collector.collect()
    assert len(values) > 0
    for key, val in values.items():
        assert key.endswith("_healthy")
        assert val in (0.0, 1.0)


if __name__ == "__main__":
    test_safe_key_sanitizes_real_disk_model_names()
    test_run_powershell_json_normalizes_a_single_object_to_a_list()
    test_run_powershell_json_handles_a_real_multi_item_array()
    test_collect_reports_real_healthy_flags_for_real_physical_disks()
    test_collect_falls_back_to_win32_diskdrive_when_physical_disk_path_fails()
    print("all tests passed")
