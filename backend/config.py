from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # ── OpenSearch (verified: 7.10.2, wazuh-cluster) ────────────
    opensearch_url:      str  = "https://localhost:9200"
    opensearch_user:     str  = "admin"
    opensearch_password: str  = "8mrFejtroEaBwVA.K*IJuLtBSRWNjsmp"
    opensearch_verify_ssl: bool = False

    # ── Index pattern (verified from _cat/indices) ───────────────
    # Real index: wazuh-alerts-4.x-2026.03.23
    index_wazuh_alerts: str = "wazuh-alerts-4.x-*"
    index_ai_anomaly:   str = "ai-anomaly-alerts"

    # ── AI Engine ────────────────────────────────────────────────
    ai_risk_threshold: float = 0.70
    # AI Engine runs on VPS1 (same host as OpenSearch)
    # Set true only after testing — auto-blocks via iptables
    ai_block_auto: bool = False

    # ── Remote block (SSH sang VPS Suricata) ──────────────────────
    # Đặt IP VPS Suricata (nơi traffic thực sự đi vào)
    # Để trống chuỗi "" = block local (VPS dashboard)
    suricata_vps_host: str = ""          # vd: "103.98.152.197"
    suricata_vps_user: str = "root"
    suricata_vps_key:  str = "/root/.ssh/id_rsa"  # private key path
    suricata_vps_port: int = 22
    # chain iptables trên VPS Suricata (nếu có AI_BLOCK chain dùng tên đó)
    suricata_iptables_chain: str = "AI_BLOCK"  # hoặc "INPUT"
    # Port SSH của VPS đang chạy service này (VPS Wazuh/AI local).
    # Trong mô hình hiện tại: Wazuh/AI = 22, Agent = 2222.
    ssh_protected_port: int = 22
    # Khi đổi Wi-Fi / đổi mạng, chỉ cần cập nhật danh sách IP public ở biến này.
    admin_whitelist_ips: str = "115.78.15.163"
    local_iptables_chain: str = "AI_BLOCK"

    # ── Remote block (SSH sang VPS Agent — nơi bị tấn công) ──────
    agent_vps_host: str = ""             # vd: "IP_VPS3"
    agent_vps_user: str = "root"
    agent_vps_key:  str = "/root/.ssh/id_rsa"
    # Port SSH của VPS Agent. Trong mô hình hiện tại: 2222.
    agent_vps_port: int = 22
    agent_iptables_chain: str = "AI_BLOCK"

    # ── Threat Intel ──────────────────────────────────────────────
    abuseipdb_api_key: str = "3938d64b323101a64d8b4777725fdcc85d77dbaad22f4bdbf2877d419678800851b0a8d268ecea0c"   # https://www.abuseipdb.com/account/api
    virustotal_api_key: str = "34b5e7343f6ba94262cec61fafb0e7788aa59d031f44705f0b4074007ea6ee8f"  # https://www.virustotal.com/gui/my-apikey — đặt trong .env

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
