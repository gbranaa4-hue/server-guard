from .forecast_report import (
    SimplePrediction,
    latest_predictions_from_db,
    render_report,
    generate_report_from_db,
)
from .multi_host_report import (
    HostReport,
    HostReadError,
    collect_multi_host,
    fleet_status,
    render_multi_host_report,
    generate_fleet_report,
)

__all__ = [
    "SimplePrediction",
    "latest_predictions_from_db",
    "render_report",
    "generate_report_from_db",
    "HostReport",
    "HostReadError",
    "collect_multi_host",
    "fleet_status",
    "render_multi_host_report",
    "generate_fleet_report",
]
