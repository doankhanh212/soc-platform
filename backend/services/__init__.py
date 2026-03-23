from config import get_settings

cfg = get_settings()

if cfg.is_mock:
	from services.mock_data import (
		get_recent_alerts,
		get_suricata_alerts,
		get_ai_anomaly_alerts,
		get_dashboard_kpis,
		get_top_attacking_ips,
		get_top_ips_with_geo,
		get_alerts_over_time,
		get_mitre_stats,
		get_alert_severity_breakdown,
		get_top_rules,
		get_suricata_signature_stats,
	)
else:
	from services.opensearch import (
		get_recent_alerts,
		get_suricata_alerts,
		get_ai_anomaly_alerts,
		get_dashboard_kpis,
		get_top_attacking_ips,
		get_top_ips_with_geo,
		get_alerts_over_time,
		get_mitre_stats,
		get_alert_severity_breakdown,
		get_top_rules,
		get_suricata_signature_stats,
	)

__all__ = [
	"get_recent_alerts",
	"get_suricata_alerts",
	"get_ai_anomaly_alerts",
	"get_dashboard_kpis",
	"get_top_attacking_ips",
	"get_top_ips_with_geo",
	"get_alerts_over_time",
	"get_mitre_stats",
	"get_alert_severity_breakdown",
	"get_top_rules",
	"get_suricata_signature_stats",
]
