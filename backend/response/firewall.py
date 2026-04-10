"""
Auto Response — chặn / bỏ chặn IP bằng iptables.

Tính năng:
  • Cache IP đã block (in-memory)  → tránh block trùng
  • Log file ghi lại: IP, thời gian, lý do
  • Validate + whitelist IP nội bộ
  • Hỗ trợ block REMOTE qua SSH sang VPS Suricata + VPS Agent
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

_WHITELIST_STATIC = frozenset({
    "127.0.0.1", "0.0.0.0", "::1", "10.0.0.1",
    # ── VPS IPs — KHÔNG BAO GIỜ tự block ────────────────────────
    "103.98.152.207",   # VPS Dashboard (whmcs167530)
    "103.98.152.197",   # VPS Suricata  (whmcs167551)
    # ── IP quản trị SSH — tránh lockout ─────────────────────────
    "115.78.15.163",    # Admin IP
})


def _parse_ip_list(raw: str) -> set[str]:
    out: set[str] = set()
    for item in str(raw or "").split(","):
        candidate = item.strip()
        if candidate and _valid(candidate):
            out.add(candidate)
    return out


def _get_whitelist() -> frozenset[str]:
    """Whitelist = static IPs + VPS IPs từ config (agent_vps_host, v.v.)."""
    from config import get_settings
    s = get_settings()
    extra = set()
    for host in (s.suricata_vps_host, s.agent_vps_host):
        h = str(host or "").strip()
        if h:
            extra.add(h)
    extra.update(_parse_ip_list(s.admin_whitelist_ips))
    if extra:
        return _WHITELIST_STATIC | frozenset(extra)
    return _WHITELIST_STATIC


def _build_remote_safe_command(ip: str, action: str, chain: str, protected_port: int) -> str:
    from config import get_settings

    s = get_settings()
    ssh_port = int(protected_port or 22)
    commands = [
        f"{_IPTABLES} -N {chain} 2>/dev/null || true",
        f"{_IPTABLES} -C INPUT -j {chain} 2>/dev/null || {_IPTABLES} -I INPUT 1 -j {chain}",
    ]

    for safe_ip in sorted(_parse_ip_list(s.admin_whitelist_ips)):
        commands.append(
            f"{_IPTABLES} -C {chain} -p tcp -s {safe_ip} --dport {ssh_port} -j ACCEPT 2>/dev/null || "
            f"{_IPTABLES} -I {chain} 1 -p tcp -s {safe_ip} --dport {ssh_port} -j ACCEPT"
        )

    if action == "block":
        commands.append(
            f"{_IPTABLES} -C {chain} -s {ip} -j DROP 2>/dev/null || {_IPTABLES} -I {chain} -s {ip} -j DROP"
        )
    else:
        commands.append(f"{_IPTABLES} -D {chain} -s {ip} -j DROP 2>/dev/null || true")

    return " ; ".join(commands)


def _valid(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _private(ip: str) -> bool:
    wl = _get_whitelist()
    if ip in wl:
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
    from config import get_settings

    s = get_settings()
    chains = [s.local_iptables_chain, "INPUT"]
    for chain in chains:
        try:
            result = subprocess.run(
                [_IPTABLES, "-C", chain, "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def _ensure_local_safe_chain(chain: str, protected_port: int) -> None:
    from config import get_settings

    s = get_settings()
    subprocess.run([_IPTABLES, "-N", chain], capture_output=True, text=True, timeout=5)
    jump_exists = subprocess.run(
        [_IPTABLES, "-C", "INPUT", "-j", chain],
        capture_output=True, text=True, timeout=5,
    )
    if jump_exists.returncode != 0:
        subprocess.run(
            [_IPTABLES, "-I", "INPUT", "1", "-j", chain],
            capture_output=True, text=True, timeout=5,
            check=False,
        )

    for safe_ip in sorted(_parse_ip_list(s.admin_whitelist_ips)):
        rule_exists = subprocess.run(
            [_IPTABLES, "-C", chain, "-p", "tcp", "-s", safe_ip, "--dport", str(protected_port), "-j", "ACCEPT"],
            capture_output=True, text=True, timeout=5,
        )
        if rule_exists.returncode != 0:
            subprocess.run(
                [_IPTABLES, "-I", chain, "1", "-p", "tcp", "-s", safe_ip, "--dport", str(protected_port), "-j", "ACCEPT"],
                capture_output=True, text=True, timeout=5,
                check=False,
            )


def _load_drop_rules_from_chain(chain: str) -> list[str]:
    try:
        result = subprocess.run(
            [_IPTABLES, "-S", chain],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return []
        found: list[str] = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if not parts or parts[0] != "-A":
                continue
            if "-s" not in parts or "-j" not in parts:
                continue
            try:
                target = parts[parts.index("-j") + 1]
                source_ip = parts[parts.index("-s") + 1]
            except (ValueError, IndexError):
                continue
            if target == "DROP" and _valid(source_ip) and not _private(source_ip):
                found.append(source_ip)
        return found
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def _ssh_block(ip: str, action: str, chain: str) -> dict:
    """
    Chạy iptables trên VPS Suricata (remote) qua SSH.
    action: "block" | "unblock"
    chain:  "AI_BLOCK" | "INPUT" | ...
    """
    from config import get_settings
    s = get_settings()
    if not s.suricata_vps_host:
        return {"ssh": "skipped", "reason": "SURICATA_VPS_HOST chưa được cấu hình"}
    return _ssh_block_remote(
        ip, action, chain,
        host=s.suricata_vps_host,
        user=s.suricata_vps_user,
        key=s.suricata_vps_key,
        port=s.suricata_vps_port,
        label="suricata",
    )


def _ssh_block_agent(ip: str, action: str) -> dict:
    """
    Chạy iptables trên VPS Agent (nơi bị tấn công) qua SSH.
    """
    from config import get_settings
    s = get_settings()
    if not s.agent_vps_host:
        return {"ssh": "skipped", "reason": "AGENT_VPS_HOST chưa được cấu hình"}
    return _ssh_block_remote(
        ip, action, s.agent_iptables_chain,
        host=s.agent_vps_host,
        user=s.agent_vps_user,
        key=s.agent_vps_key,
        port=s.agent_vps_port,
        label="agent",
    )


def _ssh_block_remote(
    ip: str, action: str, chain: str,
    *, host: str, user: str, key: str, port: int, label: str,
) -> dict:
    """Chạy iptables trên remote VPS qua SSH (dùng chung cho cả Suricata và Agent)."""
    cmd = _build_remote_safe_command(ip, action, chain, protected_port=port)

    ssh_cmd = [
        _SSH,
        "-i", key,
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=8",
        "-p", str(port),
        f"{user}@{host}",
        cmd,
    ]
    try:
        result = subprocess.run(
            ssh_cmd, capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return {"ssh": "ok", "host": host, "target": label}
        return {
            "ssh": "error",
            "host": host,
            "target": label,
            "stderr": result.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"ssh": "timeout", "host": host, "target": label}
    except Exception as e:
        return {"ssh": "error", "target": label, "detail": str(e)}


def load_blocked_from_iptables() -> int:
    """Đọc lại danh sách IP đang bị DROP từ iptables vào cache khi khởi động."""
    from config import get_settings

    try:
        s = get_settings()
        loaded = 0
        seen: set[str] = set()
        for chain in ("INPUT", s.local_iptables_chain):
            for ip_candidate in _load_drop_rules_from_chain(chain):
                if ip_candidate in seen:
                    continue
                with _lock:
                    _blocked.add(ip_candidate)
                seen.add(ip_candidate)
                loaded += 1
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
    Chặn IP bằng chain an toàn AI_BLOCK rồi mới DROP theo source IP.

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
        # 1. Block trên LOCAL (VPS dashboard / management) qua safe chain
        _ensure_local_safe_chain(s.local_iptables_chain, int(s.ssh_protected_port or 22))
        subprocess.run(
            [_IPTABLES, "-C", s.local_iptables_chain, "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5,
        )
        result = subprocess.run(
            [_IPTABLES, "-C", s.local_iptables_chain, "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            local_ok = True
            local_err = ""
        else:
            insert_result = subprocess.run(
                [_IPTABLES, "-I", s.local_iptables_chain, "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5,
            )
            local_ok = insert_result.returncode == 0
            local_err = insert_result.stderr.strip() if not local_ok else ""

        # 2. Block trên VPS Suricata (nơi traffic thực sự đi vào)
        ssh_result = _ssh_block(ip, "block", s.suricata_iptables_chain)

        # 3. Block trên VPS Agent (nơi bị tấn công)
        agent_result = _ssh_block_agent(ip, "block")

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
            "agent_vps": agent_result,
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
            [_IPTABLES, "-D", s.local_iptables_chain, "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5,
        )
        legacy_result = subprocess.run(
            [_IPTABLES, "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5,
        )
        local_ok = result.returncode == 0 or legacy_result.returncode == 0

        ssh_result = _ssh_block(ip, "unblock", s.suricata_iptables_chain)

        # Unblock trên VPS Agent
        agent_result = _ssh_block_agent(ip, "unblock")

        with _lock:
            _blocked.discard(ip)

        _write_log(ip, "UNBLOCK", "Manual unblock")

        return {
            "status": "unblocked",
            "ip": ip,
            "message": f"Đã bỏ chặn {ip}",
            "local": "ok" if local_ok else f"warn: {(result.stderr or legacy_result.stderr).strip()}",
            "suricata_vps": ssh_result,
            "agent_vps": agent_result,
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
