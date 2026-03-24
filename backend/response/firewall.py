"""
Auto Response — chặn / bỏ chặn IP bằng iptables.

Tính năng:
  • Cache IP đã block (in-memory)  → tránh block trùng
  • Log file ghi lại: IP, thời gian, lý do
  • Validate + whitelist IP nội bộ
"""
import logging
import ipaddress
import subprocess
import time
from pathlib import Path
from threading import Lock

log = logging.getLogger("firewall")

# ── Paths ─────────────────────────────────────────────────────────
_DATA_DIR = Path(__file__).parent.parent / "data"
_LOG_FILE = _DATA_DIR / "blocked_ips.log"

# ── Cache IP đã block ────────────────────────────────────────────
_blocked: set[str] = set()
_lock = Lock()

_WHITELIST = frozenset({"127.0.0.1", "0.0.0.0", "::1", "10.0.0.1"})


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
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


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

    try:
        result = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return {"status": "error",
                    "message": f"iptables lỗi: {result.stderr.strip()}"}

        with _lock:
            _blocked.add(ip)

        _write_log(ip, "BLOCK", reason)

        return {
            "status":    "blocked",
            "ip":        ip,
            "message":   f"Đã chặn {ip} thành công",
            "reason":    reason,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    except FileNotFoundError:
        return {"status": "error", "message": "iptables không tìm thấy trên server"}
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

    try:
        result = subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return {"status": "error",
                    "message": f"iptables lỗi: {result.stderr.strip()}"}

        with _lock:
            _blocked.discard(ip)

        _write_log(ip, "UNBLOCK", "Manual unblock")

        return {"status": "unblocked", "ip": ip,
                "message": f"Đã bỏ chặn {ip}"}

    except FileNotFoundError:
        return {"status": "error", "message": "iptables không tìm thấy trên server"}
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
