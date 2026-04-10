"""
Auto Response — chặn / bỏ chặn IP bằng iptables.

Tính năng:
  • Cache IP đã block (in-memory)  → tránh block trùng
  • Log file ghi lại: IP, thời gian, lý do
  • Validate + whitelist IP nội bộ
  • Hỗ trợ block REMOTE qua SSH sang VPS Suricata
"""
import logging
import ipaddress
import shutil
import subprocess
import time
from pathlib import Path
from threading import Lock

# Đường dẫn tuyệt đối — tránh lỗi PATH khi chạy qua systemd
_IPTABLES = shutil.which("iptables") or "/usr/sbin/iptables"
_SSH      = shutil.which("ssh")      or "/usr/bin/ssh"

log = logging.getLogger("firewall")

# ── Paths ─────────────────────────────────────────────────────────
_DATA_DIR = Path(__file__).parent.parent / "data"
_LOG_FILE = _DATA_DIR / "blocked_ips.log"

# ── Cache IP đã block ────────────────────────────────────────────
_blocked: set[str] = set()
_lock = Lock()

_WHITELIST = frozenset({
    "127.0.0.1", "0.0.0.0", "::1", "10.0.0.1",
    # ── VPS IPs — KHÔNG BAO GIỜ tự block ────────────────────────
    "103.98.152.207",   # VPS Dashboard (whmcs167530)
    "103.98.152.197",   # VPS Suricata  (whmcs167551)
    # ── IP quản trị SSH — tránh lockout ─────────────────────────
    "115.78.15.163",    # Admin IP
})


def _valid(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _private(ip: str) -> bool:
    if ip in _WHITELIST:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any([
        addr.is_private,
        addr.is_loopback,
        addr.is_link_local,
        addr.is_multicast,
        addr.is_reserved,
        addr.is_unspecified,
    ])


def _iptables_rule_exists(ip: str) -> bool:
    try:
        result = subprocess.run(
            [_IPTABLES, "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _ssh_block(ip: str, action: str, chain: str) -> dict:
    """
    Chạy iptables trên VPS Suricata (remote) qua SSH.
    action: "block" | "unblock"
    chain:  "AI_BLOCK" | "INPUT" | ...
    """
    from config import get_settings
    s = get_settings()
    if not s.suricata_vps_host:
        # Không cấu hình SSH → skip, không lỗi
        return {"ssh": "skipped", "reason": "SURICATA_VPS_HOST chưa được cấu hình"}

    if action == "block":
        cmd = f"{_IPTABLES} -I {chain} -s {ip} -j DROP"
    else:
        cmd = f"{_IPTABLES} -D {chain} -s {ip} -j DROP"

    ssh_cmd = [
        _SSH,
        "-i", s.suricata_vps_key,
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=8",
        "-p", str(s.suricata_vps_port),
        f"{s.suricata_vps_user}@{s.suricata_vps_host}",
        cmd,
    ]
    try:
        result = subprocess.run(
            ssh_cmd, capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return {"ssh": "ok", "host": s.suricata_vps_host}
        return {
            "ssh": "error",
            "host": s.suricata_vps_host,
            "stderr": result.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"ssh": "timeout", "host": s.suricata_vps_host}
    except Exception as e:
        return {"ssh": "error", "detail": str(e)}


def load_blocked_from_iptables() -> int:
    """Đọc lại danh sách IP đang bị DROP từ iptables vào cache khi khởi động."""
    try:
        result = subprocess.run(
            [_IPTABLES, "-L", "INPUT", "-n"],
            capture_output=True, text=True, timeout=10,
        )
        loaded = 0
        for line in result.stdout.splitlines():
            parts = line.split()
            # Dòng DROP thường có dạng: DROP  all  --  <ip>  0.0.0.0/0
            if len(parts) >= 4 and parts[0] == "DROP":
                ip_candidate = parts[3]
                try:
                    ipaddress.ip_address(ip_candidate)
                    if not _private(ip_candidate):
                        with _lock:
                            _blocked.add(ip_candidate)
                        loaded += 1
                except ValueError:
                    pass
        log.info("Loaded %d blocked IPs from iptables into cache", loaded)
        return loaded
    except Exception as e:
        log.warning("Could not load iptables rules: %s", e)
        return 0


def is_blocked(ip: str) -> bool:
    """Kiểm tra IP đã bị chặn chưa."""
    with _lock:
        if ip in _blocked:
            return True

    exists = _iptables_rule_exists(ip)
    if exists:
        with _lock:
            _blocked.add(ip)
    return exists


def _write_log(ip: str, action: str, reason: str):
    """Ghi log ra file data/blocked_ips.log."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {action} | IP: {ip} | Lý do: {reason}\n")
    log.info("Firewall %s: %s — %s", action, ip, reason)


# ══════════════════════════════════════════════════════════════════
# BLOCK IP
# ══════════════════════════════════════════════════════════════════

def block_ip(ip: str, reason: str = "AI Engine auto-block") -> dict:
    """
    Chặn IP bằng iptables -A INPUT -s <ip> -j DROP.

    • Kiểm tra IP hợp lệ
    • Không block IP nội bộ / whitelisted
    • Không block lại nếu đã tồn tại trong cache
    • Ghi log: IP, thời gian, lý do

    Returns: {"status": "blocked" | "already_blocked" | "error", ...}
    """
    if not _valid(ip):
        return {"status": "error", "message": f"IP không hợp lệ: {ip}"}

    if _private(ip):
        return {"status": "error", "message": f"Không chặn IP nội bộ: {ip}"}

    if is_blocked(ip):
        return {
            "status":  "already_blocked",
            "ip":      ip,
            "message": f"IP {ip} đã bị chặn trước đó",
        }

    from config import get_settings
    s = get_settings()

    try:
        # 1. Block trên LOCAL (VPS dashboard / management)
        result = subprocess.run(
            [_IPTABLES, "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5,
        )
        local_ok = result.returncode == 0
        local_err = result.stderr.strip() if not local_ok else ""

        # 2. Block trên VPS Suricata (nơi traffic thực sự đi vào)
        ssh_result = _ssh_block(ip, "block", s.suricata_iptables_chain)

        if not local_ok and ssh_result.get("ssh") not in ("ok", "skipped"):
            return {
                "status": "error",
                "message": f"Lỗi local: {local_err} | SSH: {ssh_result.get('stderr', 'unknown')}",
            }

        with _lock:
            _blocked.add(ip)

        _write_log(ip, "BLOCK", reason)

        return {
            "status":     "blocked",
            "ip":         ip,
            "message":    f"Đã chặn {ip} thành công",
            "reason":     reason,
            "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "local":      "ok" if local_ok else f"warn: {local_err}",
            "suricata_vps": ssh_result,
        }

    except FileNotFoundError:
        return {"status": "error", "message": f"iptables không tìm thấy: {_IPTABLES}"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "iptables timeout"}


# ══════════════════════════════════════════════════════════════════
# UNBLOCK IP
# ══════════════════════════════════════════════════════════════════

def unblock_ip(ip: str) -> dict:
    """Bỏ chặn IP (xóa rule iptables)."""
    if not _valid(ip):
        return {"status": "error", "message": f"IP không hợp lệ: {ip}"}

    if not is_blocked(ip):
        return {"status": "already_unblocked", "ip": ip,
                "message": f"IP {ip} chưa bị chặn"}

    from config import get_settings
    s = get_settings()

    try:
        result = subprocess.run(
            [_IPTABLES, "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5,
        )
        local_ok = result.returncode == 0

        ssh_result = _ssh_block(ip, "unblock", s.suricata_iptables_chain)

        with _lock:
            _blocked.discard(ip)

        _write_log(ip, "UNBLOCK", "Manual unblock")

        return {
            "status": "unblocked",
            "ip": ip,
            "message": f"Đã bỏ chặn {ip}",
            "local": "ok" if local_ok else f"warn: {result.stderr.strip()}",
            "suricata_vps": ssh_result,
        }

    except FileNotFoundError:
        return {"status": "error", "message": f"iptables không tìm thấy: {_IPTABLES}"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "iptables timeout"}


# ══════════════════════════════════════════════════════════════════
# QUERY
# ══════════════════════════════════════════════════════════════════

def get_blocked_list() -> list[str]:
    """Trả về danh sách IP đang bị chặn."""
    with _lock:
        return sorted(_blocked)


def get_block_log(limit: int = 50) -> list[str]:
    """Đọc N dòng gần nhất từ file log."""
    if not _LOG_FILE.exists():
        return []
    with open(_LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return [ln.strip() for ln in lines[-limit:]]
