from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # ── OpenSearch (verified: 7.10.2, wazuh-cluster) ────────────
    opensearch_url:      str  = "https://localhost:9200"
    opensearch_user:     str  = "admin"
    opensearch_password: str  = "CHANGE_ME"
    opensearch_verify_ssl: bool = False

    # ── Index pattern (verified from _cat/indices) ───────────────
    # Real index: wazuh-alerts-4.x-2026.03.23
    index_wazuh_alerts: str = "wazuh-alerts-4.x-*"
    index_ai_anomaly:   str = "ai-anomaly-alerts"

    # ── AI Engine ────────────────────────────────────────────────
    ai_risk_threshold: float = 0.75
    # AI Engine runs on VPS1 (same host as OpenSearch)
    # Set true only after testing — auto-blocks via iptables
    ai_block_auto: bool = False

    # ── WebSocket push interval ──────────────────────────────────
    ws_broadcast_interval: int = 10
    soc_mock_data: str = "false"

    @property
    def is_mock(self) -> bool:
        return self.soc_mock_data.lower() == "true"

    class Config:
        env_file = ".env"

@lru_cache
def get_settings() -> Settings:
    return Settings()
