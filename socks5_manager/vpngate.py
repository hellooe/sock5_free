#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Gate API client with disk/memory caching and OpenVPN configuration validator.
"""

import os
import io
import csv
import json
import time
import base64
import threading
import urllib.request
from typing import Optional, List, Dict, Tuple

from .config import VPN_GATE_API, API_CACHE_TTL, VPNGATE_CACHE_FILE
from .logger import get_logger

DANGEROUS_OVPN_DIRECTIVES = {
    "up", "down", "script-security", "plugin", "route-up",
    "route-pre-down", "ipchange", "client-connect", "client-disconnect",
    "tls-verify", "auth-user-pass-verify", "user", "group", "chroot", "cd", "management",
    "pkcs11-providers", "config", "auth-user-pass", "log", "log-append",
    "status", "writepid",
}

_cached_nodes: Optional[List[Dict]] = None
_cache_time: float = 0.0
_cache_lock = threading.Lock()


def _safe_int(val: str, default: int = 0) -> int:
    try:
        return int(val.strip())
    except (ValueError, TypeError):
        return default


def validate_ovpn(content: str) -> Tuple[bool, str]:
    """
    Validate OpenVPN configuration for minimum length, necessary connection directives,
    and prohibit potentially dangerous command-execution directives.
    """
    if not content or len(content) < 50:
        return False, "ovpn 内容过短或为空"

    has_client_or_remote = False
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or stripped.startswith(';'):
            continue
        first_word = stripped.split()[0].lower() if stripped.split() else ''
        if first_word in ("client", "remote"):
            has_client_or_remote = True
        if first_word in DANGEROUS_OVPN_DIRECTIVES:
            return False, f"包含不允许的危险指令: {first_word}"

    if not has_client_or_remote:
        return False, "缺少 client 或 remote 指令"
    return True, "ok"


def load_vpngate_cache_from_disk() -> Tuple[Optional[List[Dict]], float]:
    """Load cached nodes from disk if available."""
    if not os.path.exists(VPNGATE_CACHE_FILE):
        return None, 0.0
    try:
        with open(VPNGATE_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        cached_time = float(data.get("cache_time", 0.0))
        nodes = data.get("nodes", [])
        return nodes, cached_time
    except Exception as e:
        logger = get_logger()
        if logger:
            logger.warning(f"读取 VPN Gate 磁盘缓存失败: {e}")
        return None, 0.0


def save_vpngate_cache_to_disk(nodes: List[Dict], cache_time: float) -> None:
    """Save parsed nodes to disk cache atomically."""
    logger = get_logger()
    try:
        os.makedirs(os.path.dirname(os.path.abspath(VPNGATE_CACHE_FILE)), exist_ok=True)
        tmp_file = VPNGATE_CACHE_FILE + ".tmp"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(
                {"cache_time": cache_time, "total": len(nodes), "nodes": nodes},
                f,
                ensure_ascii=False,
            )
        os.replace(tmp_file, VPNGATE_CACHE_FILE)
        if logger:
            logger.info(f"已将 {len(nodes)} 个 VPN Gate 节点存入本地缓存文件: {VPNGATE_CACHE_FILE}")
    except Exception as e:
        if logger:
            logger.error(f"写入 VPN Gate 磁盘缓存失败: {e}")


def get_vpngate_cache_info() -> Dict:
    """Get metadata about the current VPN Gate cache status and file location."""
    global _cache_time
    now = time.time()
    disk_exists = os.path.exists(VPNGATE_CACHE_FILE)
    effective_time = _cache_time
    if not effective_time and disk_exists:
        try:
            effective_time = os.path.getmtime(VPNGATE_CACHE_FILE)
        except OSError:
            pass

    time_str = (
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(effective_time))
        if effective_time > 0
        else "未缓存"
    )
    return {
        "cache_file": VPNGATE_CACHE_FILE,
        "disk_exists": disk_exists,
        "cache_time": effective_time,
        "cache_time_str": time_str,
        "is_expired": (now - effective_time) >= API_CACHE_TTL if effective_time > 0 else True,
    }


def fetch_vpngate_nodes(country: Optional[str] = None, force_refresh: bool = False) -> List[Dict]:
    """
    Fetch and parse available OpenVPN nodes from VPN Gate with memory and disk caching.
    If country is specified, candidates are sorted by TotalUsers ascending (least users preferred).
    """
    global _cached_nodes, _cache_time
    logger = get_logger()
    now = time.time()

    # 1. Check in-memory cache
    with _cache_lock:
        if (
            not force_refresh
            and _cached_nodes is not None
            and (now - _cache_time) < API_CACHE_TTL
        ):
            nodes = _cached_nodes
            if country:
                matched = [n for n in nodes if n.get("country", "").upper() == country.upper()]
                matched.sort(key=lambda x: x.get("total_users", 0))
                return matched
            return list(nodes)

    # 2. Check disk cache if not forcing refresh
    disk_nodes, disk_time = (None, 0.0)
    if not force_refresh:
        disk_nodes, disk_time = load_vpngate_cache_from_disk()
        if disk_nodes and (now - disk_time) < API_CACHE_TTL:
            with _cache_lock:
                _cached_nodes = disk_nodes
                _cache_time = disk_time
            if country:
                matched = [n for n in disk_nodes if n.get("country", "").upper() == country.upper()]
                matched.sort(key=lambda x: x.get("total_users", 0))
                return matched
            return list(disk_nodes)

    # 3. Pull fresh data from VPN Gate API
    try:
        req = urllib.request.Request(VPN_GATE_API, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        if logger:
            logger.error(f"获取 VPN Gate 节点列表失败: {e}")
        # Fallback to existing disk cache if available
        if not disk_nodes:
            disk_nodes, disk_time = load_vpngate_cache_from_disk()
        if disk_nodes:
            if logger:
                logger.info(f"API 请求失败，回退使用本地磁盘旧缓存 ({len(disk_nodes)} 个节点)")
            with _cache_lock:
                _cached_nodes = disk_nodes
                _cache_time = disk_time
            if country:
                matched = [n for n in disk_nodes if n.get("country", "").upper() == country.upper()]
                matched.sort(key=lambda x: x.get("total_users", 0))
                return matched
            return list(disk_nodes)
        return []

    lines = data.splitlines()
    rows = [line for line in lines if not line.startswith("#")]
    csv_data = "\n".join(rows)
    reader = csv.reader(io.StringIO(csv_data))
    nodes: List[Dict] = []
    for parts in reader:
        if len(parts) < 15:
            continue
        (
            host,
            ip,
            score,
            ping,
            speed,
            country_long,
            country_short,
            num_sessions,
            uptime,
            total_users,
            total_traffic,
            log_type,
            operator,
            message,
            ovpn_b64,
        ) = parts[:15]

        if not ovpn_b64:
            continue
        try:
            ovpn = base64.b64decode(ovpn_b64).decode("utf-8", errors="ignore")
        except Exception:
            continue
        ok, _ = validate_ovpn(ovpn)
        if not ok:
            continue

        nodes.append({
            "host": host,
            "ip": ip,
            "score": _safe_int(score),
            "ping": _safe_int(ping),
            "speed": _safe_int(speed),
            "country_long": country_long,
            "country": country_short.upper(),
            "sessions": _safe_int(num_sessions),
            "uptime": _safe_int(uptime),
            "total_users": _safe_int(total_users),
            "total_traffic": _safe_int(total_traffic),
            "operator": operator,
            "ovpn": ovpn,
        })

    # Save to memory and disk cache
    with _cache_lock:
        _cached_nodes = nodes
        _cache_time = now
    save_vpngate_cache_to_disk(nodes, now)

    if country:
        matched = [n for n in nodes if n["country"].upper() == country.upper()]
        matched.sort(key=lambda x: x.get("total_users", 0))
        return matched
    return nodes


def get_vpngate_countries() -> List[Dict]:
    """
    Extract all distinct available countries from the API response,
    sorted by TotalUsers ascending (least users first).
    """
    nodes = fetch_vpngate_nodes()
    country_map = {}
    for n in nodes:
        c = n.get("country", "").upper()
        if not c:
            continue
        users = n.get("total_users", 0)
        c_long = n.get("country_long", "")
        if c not in country_map:
            country_map[c] = {
                "country": c,
                "country_long": c_long,
                "min_users": users,
                "total_users": users,
                "count": 1,
            }
        else:
            entry = country_map[c]
            entry["count"] += 1
            if users < entry["min_users"]:
                entry["min_users"] = users
            entry["total_users"] += users

    countries = list(country_map.values())
    # Sort by available node count descending (可用节点数多的排前面)
    countries.sort(key=lambda x: x["count"], reverse=True)
    return countries


def get_vpngate_node_by_host(host: str) -> Optional[Dict]:
    """Retrieve full node data including ovpn for a specific host or IP."""
    nodes = fetch_vpngate_nodes()
    for n in nodes:
        if n.get("host") == host or n.get("ip") == host:
            return n
    return None


def get_vpngate_nodes_summary(country: Optional[str] = None, force_refresh: bool = False) -> List[Dict]:
    """Retrieve node summary metadata for Web presentation without bulky ovpn content."""
    nodes = fetch_vpngate_nodes(country=country, force_refresh=force_refresh)
    summary_list = []
    for n in nodes:
        item = {k: v for k, v in n.items() if k != "ovpn"}
        summary_list.append(item)
    return summary_list
