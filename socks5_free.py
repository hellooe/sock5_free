#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOCKS5 节点管理器
"""

import os
import sys
import json
import time
import subprocess
import socket
import struct
import select
import threading
import signal
import logging
import urllib.request
import base64
import atexit
import argparse
import ssl
import csv
import io
import queue
import hashlib
import shutil
import secrets
import string
from logging.handlers import RotatingFileHandler, QueueHandler, QueueListener
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError

WORK_DIR = os.path.expanduser("~/socks5-vpn")
CONFIG_FILE = os.path.join(WORK_DIR, "state.json")
LOG_DIR = os.path.join(WORK_DIR, "logs")
TEMPLATE_DIR = os.path.join(WORK_DIR, "templates")
INDEX_HTML = os.path.join(TEMPLATE_DIR, "index.html")
PID_FILE = os.path.join(WORK_DIR, "daemon.pid")
CRED_FILE = os.path.join(WORK_DIR, "socks_credentials.json")

CHECK_INTERVAL = 15
MAX_RETRY = 6
CONSECUTIVE_FAILURES = 2
VPN_GATE_API = "https://www.vpngate.net/api/iphone/"
HEALTH_CHECK_WORKERS = 8
API_CACHE_TTL = 300
PROXY_MAX_WORKERS = 128
STATE_SAVE_DELAY = 2.0
OVPN_CONNECT_TIMEOUT = 25
HEALTH_CURL_TIMEOUT = 6

API_ADDR = "127.0.0.1"
API_PORT = 8899
API_TOKEN: Optional[str] = None
SSL_CERT: Optional[str] = None
SSL_KEY: Optional[str] = None
SOCKS_USER: Optional[str] = None
SOCKS_PASS: Optional[str] = None

logger: Optional[logging.Logger] = None
audit_logger: Optional[logging.Logger] = None


def setup_logger(name: str) -> logging.Logger:
    lg = logging.getLogger(name)
    if lg.handlers:
        return lg
    lg.setLevel(logging.INFO)
    os.makedirs(LOG_DIR, exist_ok=True)
    fh = RotatingFileHandler(
        os.path.join(LOG_DIR, f"{name}.log"),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    log_queue: queue.Queue = queue.Queue(-1)
    qh = QueueHandler(log_queue)
    lg.addHandler(qh)
    listener = QueueListener(log_queue, fh)
    listener.start()

    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    lg.addHandler(sh)
    return lg


def _recv_exact(conn: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        except (socket.error, OSError):
            return None
    return bytes(buf)


def check_dependencies() -> List[str]:
    required = ["openvpn", "curl", "ip", "iptables"]
    return [cmd for cmd in required if shutil.which(cmd) is None]


def is_port_free(port: int, host: str = "0.0.0.0") -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False


def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def validate_ovpn(content: str) -> Tuple[bool, str]:
    if not content or len(content) < 50:
        return False, "ovpn 内容过短或为空"

    dangerous = {
        "up", "down", "script-security", "plugin", "route-up",
        "route-pre-down", "ipchange", "client-connect", "client-disconnect",
        "tls-verify", "auth-user-pass-verify", "user", "group", "chroot", "cd", "management"
    }

    has_client_or_remote = False
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        tokens = line.split()
        if not tokens:
            continue
        cmd = tokens[0].lower()
        if cmd in ("client", "remote"):
            has_client_or_remote = True
        if cmd in dangerous:
            return False, f"检测到违规或危险指令: {cmd}"

    if not has_client_or_remote:
        return False, "缺少 client 或 remote 指令"
    return True, "ok"


_cached_nodes: Optional[List[Dict]] = None
_cache_time: float = 0.0
_cache_lock = threading.Lock()


def fetch_vpngate_nodes(country: Optional[str] = None, force_refresh: bool = False) -> List[Dict]:
    global _cached_nodes, _cache_time
    now = time.time()
    with _cache_lock:
        if (
            not force_refresh
            and _cached_nodes is not None
            and (now - _cache_time) < API_CACHE_TTL
        ):
            nodes = _cached_nodes
            if country:
                return [n for n in nodes if n.get("country", "").upper() == country.upper()]
            return list(nodes)

    try:
        req = urllib.request.Request(VPN_GATE_API, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        if logger:
            logger.error(f"获取 VPN Gate 节点列表失败: {e}")
        return []

    lines = data.splitlines()
    rows = [line for line in lines if not line.startswith("#")]
    csv_data = "\n".join(rows)
    reader = csv.reader(io.StringIO(csv_data))
    nodes: List[Dict] = []
    for parts in reader:
        if len(parts) < 15:
            continue
        host, ip, _, _, _, _, country_short, _, _, _, _, _, _, _, ovpn_b64 = parts[:15]
        if not ovpn_b64:
            continue
        try:
            ovpn = base64.b64decode(ovpn_b64).decode("utf-8", errors="ignore")
        except Exception:
            continue
        ok, _ = validate_ovpn(ovpn)
        if not ok:
            continue
        nodes.append({"host": host, "ip": ip, "country": country_short, "ovpn": ovpn})

    with _cache_lock:
        _cached_nodes = nodes
        _cache_time = now

    if country:
        return [n for n in nodes if n["country"].upper() == country.upper()]
    return nodes


@dataclass
class NodeState:
    name: str
    port: int
    country: Optional[str]
    ovpn_content: str
    ext_ip: Optional[str] = None
    consecutive_failures: int = 0
    running: bool = False
    retry_count: int = 0
    retry_candidates: List[str] = field(default_factory=list)


class StateManager:
    def __init__(self, config_file: str = CONFIG_FILE):
        self.config_file = config_file
        self.nodes: Dict[str, NodeState] = {}
        self._lock = threading.RLock()
        self._dirty = False
        self._save_timer: Optional[threading.Timer] = None
        self._shutdown = False
        self.load()

    def load(self) -> None:
        if not os.path.exists(self.config_file):
            return
        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            fields = set(NodeState.__dataclass_fields__.keys())
            for name, state_data in data.get("nodes", {}).items():
                filtered = {k: v for k, v in state_data.items() if k in fields}
                filtered["running"] = False
                filtered["ext_ip"] = None
                filtered["consecutive_failures"] = 0
                filtered["retry_count"] = 0
                self.nodes[name] = NodeState(**filtered)
            if logger:
                logger.info(f"成功加载 {len(self.nodes)} 个节点状态")
        except json.JSONDecodeError as e:
            if logger:
                logger.error(f"状态文件损坏，备份并重建: {e}")
            backup = self.config_file + ".bak"
            try:
                os.rename(self.config_file, backup)
            except OSError:
                pass
            self.nodes = {}
            self._save_unlocked()
        except Exception as e:
            if logger:
                logger.error(f"加载节点状态失败: {e}")

    def _save_unlocked(self) -> None:
        data = {"nodes": {}}
        for name, state in self.nodes.items():
            data["nodes"][name] = {
                "name": state.name,
                "port": state.port,
                "country": state.country,
                "ovpn_content": state.ovpn_content,
                "retry_candidates": state.retry_candidates,
            }
        tmp_file = self.config_file + ".tmp"
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(tmp_file, self.config_file)
        except OSError as e:
            if logger:
                logger.error(f"保存状态文件失败: {e}")

    def save(self) -> None:
        with self._lock:
            self._save_unlocked()

    def mark_dirty(self) -> None:
        if self._shutdown:
            return
        with self._lock:
            if self._dirty:
                return
            self._dirty = True
            if self._save_timer is not None:
                self._save_timer.cancel()
            self._save_timer = threading.Timer(STATE_SAVE_DELAY, self._delayed_save)
            self._save_timer.daemon = True
            self._save_timer.start()

    def _delayed_save(self) -> None:
        with self._lock:
            self._save_timer = None
            if not self._dirty:
                return
            self._dirty = False
            self._save_unlocked()

    def close(self) -> None:
        self._shutdown = True
        with self._lock:
            if self._save_timer is not None:
                self._save_timer.cancel()
                self._save_timer = None
            self._save_unlocked()

    def get(self, name: str) -> Optional[NodeState]:
        with self._lock:
            return self.nodes.get(name)

    def add(self, state: NodeState) -> None:
        with self._lock:
            self.nodes[state.name] = state
        self.mark_dirty()
        if audit_logger:
            audit_logger.info(f"ADD node {state.name} port={state.port} country={state.country}")

    def remove(self, name: str) -> None:
        with self._lock:
            if name in self.nodes:
                del self.nodes[name]
        self.mark_dirty()
        if audit_logger:
            audit_logger.info(f"REMOVE node {name}")

    def update_runtime(self, name: str, **kwargs) -> None:
        with self._lock:
            if name not in self.nodes:
                return
            node = self.nodes[name]
            for key, value in kwargs.items():
                if hasattr(node, key):
                    setattr(node, key, value)

    def update_ovpn(self, name: str, ovpn_content: str, host_hint: str = "") -> None:
        with self._lock:
            if name not in self.nodes:
                return
            node = self.nodes[name]
            node.ovpn_content = ovpn_content
            if host_hint:
                node.retry_candidates.append(host_hint)
                if len(node.retry_candidates) > 20:
                    node.retry_candidates = node.retry_candidates[-20:]
        self.mark_dirty()


class VpnNodeManager:
    def __init__(self, state_mgr: StateManager):
        self.state_mgr = state_mgr
        self.ovpn_processes: Dict[str, subprocess.Popen] = {}
        self.proxy_processes: Dict[str, subprocess.Popen] = {}
        self.allocated_subnets: Dict[str, int] = {}
        self.health_executor = ThreadPoolExecutor(
            max_workers=HEALTH_CHECK_WORKERS, thread_name_prefix="health"
        )
        self.restart_executor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="restart"
        )
        self.restarting_nodes: set = set()
        self._lock = threading.Lock()

    def _get_netns_name(self, name: str) -> str:
        safe = hashlib.md5(name.encode()).hexdigest()[:10]
        return f"vpn-{safe}"

    def _allocate_subnet_id(self, name: str) -> int:
        with self._lock:
            if name in self.allocated_subnets:
                return self.allocated_subnets[name]
            used = set(self.allocated_subnets.values())
            for sub_id in range(10, 250):
                if sub_id not in used:
                    self.allocated_subnets[name] = sub_id
                    return sub_id
            raise RuntimeError("没有可用的 CIDR 子网网段")

    def _release_subnet_id(self, name: str) -> None:
        with self._lock:
            self.allocated_subnets.pop(name, None)

    def _setup_netns(self, name: str, port: int) -> bool:
        netns = self._get_netns_name(name)
        sub_id = self._allocate_subnet_id(name)
        name_hash = hashlib.md5(name.encode()).hexdigest()[:8]
        veth_host = f"vh-{name_hash}"
        veth_ns = f"vn-{name_hash}"

        self._cleanup_netns(name, port)
        try:
            subprocess.run(
                ["ip", "netns", "add", netns], check=True, capture_output=True, timeout=5
            )
            subprocess.run(
                ["ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_ns],
                check=True,
                capture_output=True,
                timeout=5,
            )
            subprocess.run(
                ["ip", "link", "set", veth_ns, "netns", netns],
                check=True,
                capture_output=True,
                timeout=5,
            )

            subprocess.run(
                ["ip", "addr", "add", f"10.200.{sub_id}.1/24", "dev", veth_host],
                check=True,
                capture_output=True,
                timeout=5,
            )
            subprocess.run(
                ["ip", "link", "set", veth_host, "up"],
                check=True,
                capture_output=True,
                timeout=5,
            )

            subprocess.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    netns,
                    "ip",
                    "addr",
                    "add",
                    f"10.200.{sub_id}.2/24",
                    "dev",
                    veth_ns,
                ],
                check=True,
                capture_output=True,
                timeout=5,
            )
            subprocess.run(
                ["ip", "netns", "exec", netns, "ip", "link", "set", veth_ns, "up"],
                check=True,
                capture_output=True,
                timeout=5,
            )
            subprocess.run(
                ["ip", "netns", "exec", netns, "ip", "link", "set", "lo", "up"],
                check=True,
                capture_output=True,
                timeout=5,
            )
            subprocess.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    netns,
                    "ip",
                    "route",
                    "add",
                    "default",
                    "via",
                    f"10.200.{sub_id}.1",
                ],
                check=True,
                capture_output=True,
                timeout=5,
            )

            check_masq = subprocess.run(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-C",
                    "POSTROUTING",
                    "-s",
                    f"10.200.{sub_id}.0/24",
                    "!",
                    "-o",
                    veth_host,
                    "-j",
                    "MASQUERADE",
                ],
                capture_output=True,
                check=False,
            )
            if check_masq.returncode != 0:
                subprocess.run(
                    [
                        "iptables",
                        "-t",
                        "nat",
                        "-A",
                        "POSTROUTING",
                        "-s",
                        f"10.200.{sub_id}.0/24",
                        "!",
                        "-o",
                        veth_host,
                        "-j",
                        "MASQUERADE",
                    ],
                    check=True,
                    capture_output=True,
                    timeout=5,
                )

            subprocess.run(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    "PREROUTING",
                    "-p",
                    "tcp",
                    "--dport",
                    str(port),
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"10.200.{sub_id}.2:{port}",
                ],
                check=True,
                capture_output=True,
                timeout=5,
            )
            subprocess.run(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    "OUTPUT",
                    "-p",
                    "tcp",
                    "-d",
                    "127.0.0.1",
                    "--dport",
                    str(port),
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"10.200.{sub_id}.2:{port}",
                ],
                check=True,
                capture_output=True,
                timeout=5,
            )

            netns_dns_dir = f"/etc/netns/{netns}"
            os.makedirs(netns_dns_dir, exist_ok=True)
            with open(f"{netns_dns_dir}/resolv.conf", "w", encoding="utf-8") as f:
                f.write("nameserver 8.8.8.8\nnameserver 1.1.1.1\n")

            return True
        except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired) as e:
            err = getattr(e, "stderr", b"")
            if isinstance(err, bytes):
                err = err.decode(errors="ignore")
            if logger:
                logger.error(f"创建网络命名空间失败 [{name}]: {err or e}")
            self._cleanup_netns(name, port)
            return False

    def _cleanup_netns(self, name: str, port: Optional[int] = None) -> None:
        netns = self._get_netns_name(name)
        with self._lock:
            sub_id = self.allocated_subnets.get(name)
        name_hash = hashlib.md5(name.encode()).hexdigest()[:8]
        veth_host = f"vh-{name_hash}"

        if sub_id is not None:
            subprocess.run(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-s",
                    f"10.200.{sub_id}.0/24",
                    "!",
                    "-o",
                    veth_host,
                    "-j",
                    "MASQUERADE",
                ],
                stderr=subprocess.DEVNULL,
                check=False,
            )

            if port is not None:
                subprocess.run(
                    [
                        "iptables",
                        "-t",
                        "nat",
                        "-D",
                        "PREROUTING",
                        "-p",
                        "tcp",
                        "--dport",
                        str(port),
                        "-j",
                        "DNAT",
                        "--to-destination",
                        f"10.200.{sub_id}.2:{port}",
                    ],
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                subprocess.run(
                    [
                        "iptables",
                        "-t",
                        "nat",
                        "-D",
                        "OUTPUT",
                        "-p",
                        "tcp",
                        "-d",
                        "127.0.0.1",
                        "--dport",
                        str(port),
                        "-j",
                        "DNAT",
                        "--to-destination",
                        f"10.200.{sub_id}.2:{port}",
                    ],
                    stderr=subprocess.DEVNULL,
                    check=False,
                )

        subprocess.run(
            ["ip", "link", "del", veth_host], stderr=subprocess.DEVNULL, check=False
        )
        subprocess.run(
            ["ip", "netns", "del", netns], stderr=subprocess.DEVNULL, check=False
        )

        netns_dns_dir = f"/etc/netns/{netns}"
        if os.path.exists(netns_dns_dir):
            try:
                shutil.rmtree(netns_dns_dir)
            except OSError:
                pass
        self._release_subnet_id(name)

    def _get_ovpn_file(self, name: str) -> str:
        return os.path.join(WORK_DIR, f"{name}.ovpn")

    def _get_ext_ip_via_netns(self, netns: str) -> Optional[str]:
        check_tun = subprocess.run(
            ["ip", "netns", "exec", netns, "ip", "link", "show", "dev", "tun0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if check_tun.returncode != 0:
            return None

        endpoints = ["ifconfig.me", "api.ipify.org", "icanhazip.com", "ipinfo.io/ip"]
        for ep in endpoints:
            try:
                res = subprocess.run(
                    [
                        "ip",
                        "netns",
                        "exec",
                        netns,
                        "curl",
                        "-s",
                        "--max-time",
                        "3",
                        ep,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=5,
                )
                if res.returncode == 0 and res.stdout.strip():
                    ip = res.stdout.strip()
                    if "." in ip or ":" in ip:
                        return ip
            except Exception:
                continue
        return None

    def _probe_via_socks(self, port: int) -> Optional[str]:
        endpoints = ["ifconfig.me", "api.ipify.org", "icanhazip.com"]
        auth = f"{SOCKS_USER}:{SOCKS_PASS}" if SOCKS_USER and SOCKS_PASS else None
        for ep in endpoints:
            cmd = [
                "curl",
                "-s",
                "--max-time",
                str(HEALTH_CURL_TIMEOUT),
                "--socks5-hostname",
                f"127.0.0.1:{port}",
            ]
            if auth:
                cmd.extend(["--proxy-user", auth])
            cmd.append(f"http://{ep}")
            try:
                res = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=HEALTH_CURL_TIMEOUT + 2,
                )
                if res.returncode == 0 and res.stdout.strip():
                    ip = res.stdout.strip()
                    if "." in ip or ":" in ip:
                        return ip
            except Exception:
                continue
        return None

    def start_node(self, name: str) -> bool:
        state = self.state_mgr.get(name)
        if not state:
            if logger:
                logger.error(f"节点 {name} 不存在")
            return False

        with self._lock:
            if name in self.ovpn_processes or name in self.proxy_processes:
                if logger:
                    logger.warning(f"节点 {name} 已有进程在运行，先清理")
                self.stop_node(name)

        netns = self._get_netns_name(name)
        if not self._setup_netns(name, state.port):
            return False

        ovpn_file = self._get_ovpn_file(name)
        try:
            with open(ovpn_file, "w", encoding="utf-8") as f:
                f.write(state.ovpn_content)
        except OSError as e:
            if logger:
                logger.error(f"写入 ovpn 文件失败: {e}")
            self._cleanup_netns(name, state.port)
            return False

        log_file = os.path.join(LOG_DIR, f"ovpn-{name}.log")
        try:
            with open(log_file, "a", encoding="utf-8") as logf:
                ovpn_proc = subprocess.Popen(
                    [
                        "ip",
                        "netns",
                        "exec",
                        netns,
                        "openvpn",
                        "--config",
                        ovpn_file,
                        "--dev",
                        "tun",
                        "--verb",
                        "3",
                    ],
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            with self._lock:
                self.ovpn_processes[name] = ovpn_proc
        except OSError as e:
            if logger:
                logger.error(f"启动 OpenVPN 进程失败: {e}")
            self._cleanup_netns(name, state.port)
            return False

        deadline = time.time() + OVPN_CONNECT_TIMEOUT
        ext_ip = None
        while time.time() < deadline:
            if ovpn_proc.poll() is not None:
                if logger:
                    logger.error(f"OpenVPN 启动即失败，详情见日志: {log_file}")
                self.stop_node(name)
                return False
            time.sleep(2)
            ext_ip = self._get_ext_ip_via_netns(netns)
            if ext_ip:
                break

        if not ext_ip:
            if logger:
                logger.warning(f"节点 {name} 建立 VPN 隧道超时（{OVPN_CONNECT_TIMEOUT}s）")
        else:
            if logger:
                logger.info(f"节点 {name} 隧道就绪，出口 IP: {ext_ip}")

        proxy_cmd = [
            "ip",
            "netns",
            "exec",
            netns,
            sys.executable,
            os.path.abspath(__file__),
            "proxy",
            "--port",
            str(state.port),
        ]
        if SOCKS_USER and SOCKS_PASS:
            proxy_cmd.extend(["--user", SOCKS_USER, "--pass", SOCKS_PASS])

        try:
            proxy_log_path = os.path.join(LOG_DIR, f"proxy-{name}.log")
            with open(proxy_log_path, "a", encoding="utf-8") as proxy_log:
                proxy_proc = subprocess.Popen(
                    proxy_cmd,
                    stdout=proxy_log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            with self._lock:
                self.proxy_processes[name] = proxy_proc
        except OSError as e:
            if logger:
                logger.error(f"启动 SOCKS5 代理子进程失败: {e}")
            self.stop_node(name)
            return False

        time.sleep(1.5)
        if proxy_proc.poll() is not None:
            if logger:
                logger.error(f"SOCKS5 代理启动失败 [{name}]")
            self.stop_node(name)
            return False

        self.state_mgr.update_runtime(
            name,
            running=True,
            ext_ip=ext_ip,
            consecutive_failures=0,
            retry_count=0,
        )
        if audit_logger:
            audit_logger.info(f"START node {name} port={state.port} ext_ip={ext_ip}")
        return True

    def stop_node(self, name: str) -> None:
        state = self.state_mgr.get(name)
        port = state.port if state else None
        netns = self._get_netns_name(name)

        subprocess.run(
            ["ip", "netns", "exec", netns, "pkill", "-9", "-f", "openvpn"],
            stderr=subprocess.DEVNULL,
            check=False,
        )
        script_name = os.path.basename(__file__)
        subprocess.run(
            ["ip", "netns", "exec", netns, "pkill", "-9", "-f", script_name],
            stderr=subprocess.DEVNULL,
            check=False,
        )

        with self._lock:
            if name in self.proxy_processes:
                try:
                    p = self.proxy_processes.pop(name)
                    p.kill()
                    p.wait(timeout=2)
                except Exception as e:
                    if logger:
                        logger.debug(f"停止代理进程异常 [{name}]: {e}")

            if name in self.ovpn_processes:
                try:
                    p = self.ovpn_processes.pop(name)
                    p.kill()
                    p.wait(timeout=2)
                except Exception as e:
                    if logger:
                        logger.debug(f"停止 OpenVPN 进程异常 [{name}]: {e}")

        self._cleanup_netns(name, port)
        self.state_mgr.update_runtime(name, running=False, ext_ip=None)
        if logger:
            logger.info(f"节点 {name} 已停止并清理")
        if audit_logger:
            audit_logger.info(f"STOP node {name}")

    def health_check(self) -> None:
        futures = {}
        for name, state in list(self.state_mgr.nodes.items()):
            if not state.running:
                continue
            future = self.health_executor.submit(self._check_single_node, name)
            futures[future] = name

        try:
            for future in as_completed(futures, timeout=CHECK_INTERVAL - 2):
                name = futures[future]
                state = self.state_mgr.get(name)
                if not state:
                    continue
                try:
                    result = future.result()
                except Exception as e:
                    if logger:
                        logger.error(f"健康检查异常 [{name}]: {e}")
                    continue

                if result == "proxy_dead":
                    if logger:
                        logger.warning(f"节点 {name} 代理进程已退出，触发异步重启")
                    self._trigger_async_restart(name, force_restart=True)
                elif result is None:
                    new_failures = state.consecutive_failures + 1
                    if logger:
                        logger.warning(
                            f"节点 {name} SOCKS5 探测失败 ({new_failures}/{CONSECUTIVE_FAILURES})"
                        )
                    self.state_mgr.update_runtime(name, consecutive_failures=new_failures)
                else:
                    self.state_mgr.update_runtime(
                        name, ext_ip=result, consecutive_failures=0
                    )

                state = self.state_mgr.get(name)
                if state and state.consecutive_failures >= CONSECUTIVE_FAILURES:
                    if logger:
                        logger.warning(f"节点 {name} 连续失败，触发故障转移")
                    self._trigger_async_restart(name)
        except FuturesTimeoutError:
            if logger:
                logger.warning("本轮健康检查超时，部分节点未完成探测")

    def _check_single_node(self, name: str) -> Optional[str]:
        state = self.state_mgr.get(name)
        if not state or not state.running:
            return None

        with self._lock:
            proc = self.proxy_processes.get(name)
        if proc is None or proc.poll() is not None:
            return "proxy_dead"

        return self._probe_via_socks(state.port)

    def _trigger_async_restart(self, name: str, force_restart: bool = False) -> None:
        with self._lock:
            if name in self.restarting_nodes:
                return
            self.restarting_nodes.add(name)
        self.restart_executor.submit(self._async_restart_wrapper, name, force_restart)

    def _async_restart_wrapper(self, name: str, force_restart: bool) -> None:
        try:
            self._restart_with_retry(name, force_restart)
        finally:
            with self._lock:
                self.restarting_nodes.discard(name)

    def _restart_with_retry(self, name: str, force_restart: bool = False) -> None:
        state = self.state_mgr.get(name)
        if not state:
            return

        self.stop_node(name)
        time.sleep(1.5)

        if self.start_node(name):
            return

        if force_restart:
            self.state_mgr.update_runtime(name, running=False)
            return

        if state.country and state.retry_count < MAX_RETRY:
            new_retry = state.retry_count + 1
            self.state_mgr.update_runtime(name, retry_count=new_retry)

            candidates = fetch_vpngate_nodes(state.country, force_refresh=True)
            for cand in candidates:
                if cand["ovpn"] == state.ovpn_content:
                    continue
                self.state_mgr.update_ovpn(name, cand["ovpn"], cand.get("host", ""))
                if self.start_node(name):
                    if logger:
                        logger.info(
                            f"节点 {name} 已热替换为: {cand.get('host', 'unknown')}"
                        )
                    if audit_logger:
                        audit_logger.info(
                            f"REPLACE node {name} -> {cand.get('host', 'unknown')}"
                        )
                    return

        self.state_mgr.update_runtime(name, running=False)
        if logger:
            logger.error(f"节点 {name} 多次重试后仍无法启动，已标记停止")

    def close(self) -> None:
        with self._lock:
            nodes_to_stop = list(self.ovpn_processes.keys()) + list(self.proxy_processes.keys())
        for name in nodes_to_stop:
            try:
                self.stop_node(name)
            except Exception:
                pass
        self.health_executor.shutdown(wait=False, cancel_futures=True)
        self.restart_executor.shutdown(wait=False, cancel_futures=True)


class Socks5Proxy:
    def __init__(
        self,
        port: int,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.port = port
        self.username = username
        self.password = password
        self.require_auth = bool(username and password)
        self.running = True
        self.executor = ThreadPoolExecutor(
            max_workers=PROXY_MAX_WORKERS, thread_name_prefix="socks"
        )

    def _forward(self, conn: socket.socket, target: socket.socket) -> None:
        try:
            while self.running:
                r, _, _ = select.select([conn, target], [], [], 1.0)
                if not r:
                    continue
                if conn in r:
                    data = conn.recv(8192)
                    if not data:
                        break
                    target.sendall(data)
                if target in r:
                    data = target.recv(8192)
                    if not data:
                        break
                    conn.sendall(data)
        except Exception:
            pass
        finally:
            for s in (conn, target):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass

    def _handle_client(self, conn: socket.socket) -> None:
        try:
            header = _recv_exact(conn, 2)
            if not header or header[0] != 5:
                return
            nmethods = header[1]
            methods = _recv_exact(conn, nmethods)
            if methods is None:
                return

            if self.require_auth:
                if 2 not in methods:
                    conn.sendall(b"\x05\xff")
                    return
                conn.sendall(b"\x05\x02")
                auth_header = _recv_exact(conn, 2)
                if not auth_header or auth_header[0] != 1:
                    return
                ulen = auth_header[1]
                uname = _recv_exact(conn, ulen)
                if uname is None:
                    return
                plen_b = _recv_exact(conn, 1)
                if plen_b is None:
                    return
                plen = plen_b[0]
                passwd = _recv_exact(conn, plen)
                if passwd is None:
                    return
                if (
                    uname.decode("utf-8", errors="ignore") != self.username
                    or passwd.decode("utf-8", errors="ignore") != self.password
                ):
                    conn.sendall(b"\x01\x01")
                    return
                conn.sendall(b"\x01\x00")
            else:
                if 0 not in methods:
                    conn.sendall(b"\x05\xff")
                    return
                conn.sendall(b"\x05\x00")

            req = _recv_exact(conn, 4)
            if not req or req[0] != 5 or req[1] != 1:
                return

            addr_type = req[3]
            if addr_type == 1:
                raw_ip = _recv_exact(conn, 4)
                if not raw_ip:
                    return
                addr = socket.inet_ntoa(raw_ip)
            elif addr_type == 3:
                raw_len = _recv_exact(conn, 1)
                if not raw_len:
                    return
                domain_len = raw_len[0]
                raw_domain = _recv_exact(conn, domain_len)
                if not raw_domain:
                    return
                addr = raw_domain.decode("utf-8", errors="ignore")
            elif addr_type == 4:
                raw_ip6 = _recv_exact(conn, 16)
                if not raw_ip6:
                    return
                addr = socket.inet_ntop(socket.AF_INET6, raw_ip6)
            else:
                return

            raw_port = _recv_exact(conn, 2)
            if not raw_port:
                return
            port = struct.unpack(">H", raw_port)[0]

            try:
                target = socket.create_connection((addr, port), timeout=12)
            except Exception:
                conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            conn.settimeout(None)
            target.settimeout(None)

            self._forward(conn, target)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def run(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", self.port))
        except OSError as e:
            if logger:
                logger.error(f"代理绑定端口 {self.port} 失败: {e}")
            return
        server.listen(256)
        server.settimeout(1.0)
        if logger:
            logger.info(
                f"SOCKS5 代理启动 port={self.port} auth={'yes' if self.require_auth else 'no'}"
            )
        try:
            while self.running:
                try:
                    conn, _ = server.accept()
                    conn.settimeout(30)
                    self.executor.submit(self._handle_client, conn)
                except socket.timeout:
                    continue
                except Exception:
                    break
        finally:
            server.close()
            self.executor.shutdown(wait=False, cancel_futures=True)


class APIHandler(BaseHTTPRequestHandler):
    manager = None

    def log_message(self, format: str, *args) -> None:
        if logger:
            logger.debug("%s - %s", self.address_string(), format % args)

    def _check_auth(self) -> bool:
        token = self.headers.get("X-API-Token")
        if not token or token != API_TOKEN:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"Unauthorized"}')
            return False
        return True

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/", "/index.html"):
            self.send_html(INDEX_HTML)
            return

        if not self._check_auth():
            return

        if path == "/api/nodes":
            self.send_json(self._get_nodes())
        elif path == "/api/status":
            self.send_json(self._get_status())
        elif path == "/api/credentials":
            self.send_json(
                {
                    "socks_user": SOCKS_USER,
                    "socks_pass": SOCKS_PASS,
                }
            )
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if not self._check_auth():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/node/add":
            self._handle_add_node()
        elif path == "/api/node/del":
            self._handle_del_node()
        else:
            self.send_error(404)

    def _handle_add_node(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 2 * 1024 * 1024:
                self.send_json({"error": "请求体过大"}, 400)
                return
            body = self.rfile.read(length)
            data = json.loads(body)
        except Exception as e:
            self.send_json({"error": f"请求格式错误: {e}"}, 400)
            return

        try:
            name = data.get("name") or f"{data.get('country', 'node')}_{int(time.time())}"
            if not isinstance(name, str) or not name.strip():
                self.send_json({"error": "节点名称无效"}, 400)
                return
            name = name.strip()[:64]

            if name in self.manager.state_mgr.nodes:
                self.send_json({"error": f'节点 "{name}" 已存在'}, 400)
                return

            port = data.get("port")
            if port is not None:
                try:
                    port = int(port)
                except (TypeError, ValueError):
                    self.send_json({"error": "端口必须是整数"}, 400)
                    return
                if not (1024 <= port <= 65535):
                    self.send_json({"error": "端口范围 1024-65535"}, 400)
                    return
                if any(s.port == port for s in self.manager.state_mgr.nodes.values()):
                    self.send_json({"error": f"端口 {port} 已被本系统占用"}, 400)
                    return
                if not is_port_free(port):
                    self.send_json({"error": f"端口 {port} 系统已被占用"}, 400)
                    return
            else:
                port = self._get_free_port()
                if port is None:
                    self.send_json({"error": "无可用端口"}, 500)
                    return

            if "country" in data and data["country"]:
                nodes = fetch_vpngate_nodes(data["country"])
                if not nodes:
                    self.send_json({"error": "未获取到该国家可用的节点"}, 400)
                    return
                ovpn = nodes[0]["ovpn"]
                country = nodes[0]["country"]
            else:
                ovpn = data.get("ovpn_content")
                if not ovpn or not isinstance(ovpn, str):
                    self.send_json({"error": "缺少 ovpn_content 或 country"}, 400)
                    return
                ok, msg = validate_ovpn(ovpn)
                if not ok:
                    self.send_json({"error": f"ovpn 校验失败: {msg}"}, 400)
                    return
                country = data.get("country")

            state = NodeState(name=name, port=port, country=country, ovpn_content=ovpn)
            self.manager.state_mgr.add(state)

            if not self.manager.node_mgr.start_node(name):
                self.manager.state_mgr.remove(name)
                self.send_json(
                    {"error": "启动节点失败，请检查 OpenVPN 连接日志"}, 500
                )
                return

            self.send_json({"status": "ok", "node": {"name": name, "port": port}})
        except Exception as e:
            if logger:
                logger.exception("添加节点异常")
            self.send_json({"error": str(e)}, 500)

    def _handle_del_node(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length))
            name = data.get("name")
            if not name:
                self.send_json({"error": "缺少节点名称"}, 400)
                return
            self.manager.node_mgr.stop_node(name)
            self.manager.state_mgr.remove(name)
            self.send_json({"status": "ok"})
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def _get_nodes(self) -> List[Dict]:
        return [
            {
                "name": s.name,
                "port": s.port,
                "country": s.country,
                "running": s.running,
                "ext_ip": s.ext_ip,
                "failures": s.consecutive_failures,
            }
            for s in self.manager.state_mgr.nodes.values()
        ]

    def _get_status(self) -> Dict:
        return {
            "total": len(self.manager.state_mgr.nodes),
            "running": sum(
                1 for s in self.manager.state_mgr.nodes.values() if s.running
            ),
            "socks_auth_enabled": bool(SOCKS_USER and SOCKS_PASS),
        }

    def _get_free_port(self) -> Optional[int]:
        used = {s.port for s in self.manager.state_mgr.nodes.values()}
        for port in range(10801, 12000):
            if port not in used and is_port_free(port):
                return port
        return None

    def send_json(self, obj, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def send_html(self, filename: str) -> None:
        try:
            with open(filename, "rb") as f:
                html = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(html)
        except OSError:
            self.send_error(404)


class Manager:
    def __init__(self):
        self.state_mgr = StateManager()
        self.node_mgr = VpnNodeManager(self.state_mgr)
        APIHandler.manager = self

    def start_all(self) -> None:
        for name, state in list(self.state_mgr.nodes.items()):
            if not state.running:
                if logger:
                    logger.info(f"启动已配置节点: {name}")
                self.node_mgr.start_node(name)

    def stop_all(self) -> None:
        for name in list(self.state_mgr.nodes.keys()):
            self.node_mgr.stop_node(name)

    def run_health_loop(self) -> None:
        while True:
            try:
                self.node_mgr.health_check()
            except Exception as e:
                if logger:
                    logger.error(f"健康检查循环异常: {e}")
            time.sleep(CHECK_INTERVAL)

    def close(self) -> None:
        if logger:
            logger.info("正在关闭所有节点与资源...")
        self.stop_all()
        self.node_mgr.close()
        self.state_mgr.close()


def daemonize() -> None:
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)

    sys.stdout.flush()
    sys.stderr.flush()

    with open(os.devnull, "r") as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
    with open(os.devnull, "a+") as devnull:
        os.dup2(devnull.fileno(), sys.stdout.fileno())
        os.dup2(devnull.fileno(), sys.stderr.fileno())

    os.chdir("/")
    os.umask(0o027)

    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))
    atexit.register(
        lambda: os.remove(PID_FILE) if os.path.exists(PID_FILE) else None
    )


def write_index_html() -> None:
    html = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOCKS5 节点控制台</title>
<style>
:root { --bg:#0f1419; --card:#1a2332; --border:#2d3a4f; --text:#e7ecf3; --muted:#8b9bb4; --accent:#3b82f6; --ok:#22c55e; --bad:#ef4444; }
* { box-sizing:border-box; }
body { font-family: system-ui, -apple-system, sans-serif; background:var(--bg); color:var(--text); margin:0; padding:24px; line-height:1.5; }
h1 { font-size:1.5rem; margin:0 0 8px; }
.card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; margin-bottom:20px; }
table { width:100%; border-collapse:collapse; }
th, td { border-bottom:1px solid var(--border); padding:10px 12px; text-align:left; font-size:0.9rem; }
th { color:var(--muted); font-weight:600; }
.form-row { display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-bottom:12px; }
input, select, button { background:#0d1117; border:1px solid var(--border); color:var(--text); padding:8px 12px; border-radius:8px; font-size:0.9rem; }
button { background:var(--accent); border:none; cursor:pointer; font-weight:600; }
button.danger { background:var(--bad); }
button:hover { filter:brightness(1.1); }
.status-running { color:var(--ok); font-weight:600; }
.status-stopped { color:var(--bad); font-weight:600; }
#login-overlay { position:fixed; inset:0; background:rgba(0,0,0,0.75); display:flex; justify-content:center; align-items:center; z-index:100; }
#login-box { background:var(--card); padding:32px; border-radius:16px; border:1px solid var(--border); min-width:320px; }
.muted { color:var(--muted); font-size:0.85rem; }
.cred { font-family: ui-monospace, monospace; background:#0d1117; padding:8px 12px; border-radius:8px; display:inline-block; margin-top:8px; }
</style>
</head>
<body>
<div id="login-overlay">
  <div id="login-box">
    <h2 style="margin-top:0">API Token 验证</h2>
    <input type="password" id="tokenInput" placeholder="输入 API Token" style="width:100%;margin-bottom:12px">
    <button onclick="login()" style="width:100%">进入控制台</button>
  </div>
</div>

<div id="main" style="display:none; max-width:1100px; margin:0 auto">
  <h1>SOCKS5 节点管理</h1>
  <p class="muted" id="statusBar">加载中…</p>

  <div class="card">
    <div class="form-row">
      <input id="nodeName" placeholder="节点名称（可选）" style="min-width:140px">
      <select id="countrySelect">
        <option value="">选择国家</option>
        <option value="JP">日本 JP</option>
        <option value="US">美国 US</option>
        <option value="KR">韩国 KR</option>
        <option value="SG">新加坡 SG</option>
        <option value="HK">香港 HK</option>
        <option value="TW">台湾 TW</option>
        <option value="DE">德国 DE</option>
        <option value="GB">英国 GB</option>
        <option value="FR">法国 FR</option>
        <option value="CA">加拿大 CA</option>
        <option value="AU">澳大利亚 AU</option>
        <option value="NL">荷兰 NL</option>
      </select>
      <input id="portInput" placeholder="端口（空=自动）" style="width:130px">
      <button onclick="addNode()">添加动态节点</button>
      <span class="muted">|</span>
      <input type="file" id="ovpnFile" accept=".ovpn" style="max-width:180px">
      <button onclick="uploadOvpn()">上传 .ovpn</button>
    </div>
    <div id="credBox" class="muted" style="margin-top:8px"></div>
  </div>

  <div class="card" style="padding:0; overflow:auto">
    <table>
      <thead>
        <tr>
          <th>节点名</th>
          <th>SOCKS5 端口</th>
          <th>国家</th>
          <th>出口 IP</th>
          <th>状态</th>
          <th>失败次数</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody id="nodeList"></tbody>
    </table>
  </div>
</div>

<script>
let token = '';

function login() {
  token = document.getElementById('tokenInput').value.trim();
  if (!token) { alert('请输入 Token'); return; }
  sessionStorage.setItem('apiToken', token);
  document.getElementById('login-overlay').style.display = 'none';
  document.getElementById('main').style.display = 'block';
  fetchNodes();
  fetchCreds();
  setInterval(fetchNodes, 5000);
}

function getHeaders() {
  return { 'Content-Type': 'application/json', 'X-API-Token': token };
}

async function fetchCreds() {
  try {
    const r = await fetch('/api/credentials', { headers: getHeaders() });
    if (!r.ok) return;
    const c = await r.json();
    if (c.socks_user) {
      document.getElementById('credBox').innerHTML =
        'SOCKS5 认证：用户 <span class="cred">' + c.socks_user + '</span>  密码 <span class="cred">' + c.socks_pass + '</span>';
    } else {
      document.getElementById('credBox').textContent = '警告：当前 SOCKS5 未启用认证';
    }
  } catch (e) {}
}

async function fetchNodes() {
  try {
    let r = await fetch('/api/nodes', { headers: getHeaders() });
    if (r.status === 401) {
      sessionStorage.removeItem('apiToken');
      alert('Token 无效，请重新登录');
      location.reload();
      return;
    }
    const nodes = await r.json();
    const s = await (await fetch('/api/status', { headers: getHeaders() })).json();
    document.getElementById('statusBar').textContent =
      `共 ${s.total} 个节点，运行中 ${s.running} 个` +
      (s.socks_auth_enabled ? ' · SOCKS5 已启用认证' : ' · 警告：SOCKS5 无认证');
    document.getElementById('nodeList').innerHTML = nodes.map(item => `
      <tr>
        <td>${esc(item.name)}</td>
        <td>${item.port}</td>
        <td>${item.country || '-'}</td>
        <td>${item.ext_ip || '-'}</td>
        <td class="${item.running ? 'status-running' : 'status-stopped'}">
          ${item.running ? '运行中' : '已停止'}
        </td>
        <td>${item.failures || 0}</td>
        <td><button class="danger" onclick="deleteNode('${esc(item.name)}')">删除</button></td>
      </tr>
    `).join('');
  } catch (e) { console.error(e); }
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function addNode() {
  const name = document.getElementById('nodeName').value.trim() || undefined;
  const country = document.getElementById('countrySelect').value;
  const port = document.getElementById('portInput').value;
  if (!country) return alert('请选择国家');
  const data = { country };
  if (name) data.name = name;
  if (port) data.port = parseInt(port, 10);
  const r = await fetch('/api/node/add', { method: 'POST', headers: getHeaders(), body: JSON.stringify(data) });
  const j = await r.json();
  if (r.ok) { fetchNodes(); document.getElementById('nodeName').value = ''; }
  else alert(j.error || '失败');
}

async function uploadOvpn() {
  const file = document.getElementById('ovpnFile').files[0];
  if (!file) return alert('请选择 .ovpn 文件');
  const text = await file.text();
  const name = prompt('请输入节点名称:');
  if (!name) return;
  const port = document.getElementById('portInput').value;
  const data = { name, ovpn_content: text };
  if (port) data.port = parseInt(port, 10);
  const r = await fetch('/api/node/add', { method: 'POST', headers: getHeaders(), body: JSON.stringify(data) });
  const j = await r.json();
  if (r.ok) { fetchNodes(); }
  else alert(j.error || '失败');
}

async function deleteNode(name) {
  if (!confirm('确定删除节点 ' + name + '？')) return;
  const r = await fetch('/api/node/del', { method: 'POST', headers: getHeaders(), body: JSON.stringify({ name }) });
  if (r.ok) fetchNodes();
  else alert((await r.json()).error || '失败');
}

window.onload = function () {
  const saved = sessionStorage.getItem('apiToken');
  if (saved) {
    document.getElementById('tokenInput').value = saved;
    login();
  }
};
</script>
</body>
</html>
"""
    os.makedirs(TEMPLATE_DIR, exist_ok=True)
    with open(INDEX_HTML, "w", encoding="utf-8") as f:
        f.write(html)


def start_daemon(
    api_addr: str,
    api_port: int,
    api_token: Optional[str] = None,
    ssl_cert: Optional[str] = None,
    ssl_key: Optional[str] = None,
    socks_user: Optional[str] = None,
    socks_pass: Optional[str] = None,
) -> None:
    global API_ADDR, API_PORT, API_TOKEN, SSL_CERT, SSL_KEY, SOCKS_USER, SOCKS_PASS
    global logger, audit_logger

    missing = check_dependencies()
    if missing:
        print(f"缺少必要命令: {', '.join(missing)}", file=sys.stderr)
        print("请先安装 openvpn / curl / iproute2 / iptables", file=sys.stderr)
        sys.exit(1)

    if os.geteuid() != 0:
        print("警告: 建议以 root 运行（需要 netns / iptables 权限）", file=sys.stderr)

    api_token = api_token or os.environ.get("API_TOKEN")
    if not api_token:
        print("错误: 必须提供 --api-token 或设置 API_TOKEN 环境变量", file=sys.stderr)
        sys.exit(1)

    API_ADDR = api_addr
    API_PORT = api_port
    API_TOKEN = api_token
    SSL_CERT = ssl_cert
    SSL_KEY = ssl_key

    socks_user = socks_user or os.environ.get("SOCKS_USER")
    socks_pass = socks_pass or os.environ.get("SOCKS_PASS")

    if socks_user and socks_pass:
        SOCKS_USER = socks_user
        SOCKS_PASS = socks_pass
    else:
        if os.path.exists(CRED_FILE):
            try:
                with open(CRED_FILE, "r", encoding="utf-8") as f:
                    cred = json.load(f)
                SOCKS_USER = cred.get("user") or "socks"
                SOCKS_PASS = cred.get("pass") or generate_password()
            except Exception:
                SOCKS_USER = "socks"
                SOCKS_PASS = generate_password()
        else:
            SOCKS_USER = "socks"
            SOCKS_PASS = generate_password()
        try:
            os.makedirs(WORK_DIR, exist_ok=True)
            with open(CRED_FILE, "w", encoding="utf-8") as f:
                json.dump({"user": SOCKS_USER, "pass": SOCKS_PASS}, f, indent=2)
            os.chmod(CRED_FILE, 0o600)
        except OSError as e:
            print(f"无法保存凭证文件: {e}", file=sys.stderr)

    print(f"SOCKS5 认证用户: {SOCKS_USER}")
    print(f"SOCKS5 认证密码: {SOCKS_PASS}")
    print("请妥善保管，也可在 Web 控制台查看")

    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            if os.path.exists(f"/proc/{pid}"):
                print("后台进程已经在运行中")
                return
        except Exception:
            pass

    subprocess.run(
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["sysctl", "-w", "net.ipv4.conf.all.route_localnet=1"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    daemonize()

    logger = setup_logger("socks5vpn")
    audit_logger = setup_logger("audit")

    os.makedirs(WORK_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    write_index_html()

    manager = Manager()

    def sig_handler(signum, frame):
        if logger:
            logger.info("收到退出信号，开始优雅关闭...")
        manager.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    server = HTTPServer((API_ADDR, API_PORT), APIHandler)
    if SSL_CERT and SSL_KEY:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(SSL_CERT, SSL_KEY)
        server.socket = context.wrap_socket(server.socket, server_side=True)

    threading.Thread(target=server.serve_forever, daemon=True).start()
    if logger:
        logger.info(f"API/Web 服务就绪: {API_ADDR}:{API_PORT} (SSL={'yes' if SSL_CERT else 'no'})")
        logger.info(f"SOCKS 认证已启用: user={SOCKS_USER}")

    manager.start_all()
    manager.run_health_loop()


def stop_daemon() -> None:
    if not os.path.exists(PID_FILE):
        print("服务尚未运行")
        return
    try:
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            if not os.path.exists(f"/proc/{pid}"):
                break
            time.sleep(0.3)
        print("服务已停止")
    except Exception as e:
        print(f"停止服务失败: {e}")


def status_daemon() -> None:
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            if os.path.exists(f"/proc/{pid}"):
                print(f"守护服务运行中，PID: {pid}")
                return
        except Exception:
            pass
    print("服务尚未运行")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SOCKS5 节点管理器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    start_parser = subparsers.add_parser("start", help="启动后台守护进程")
    start_parser.add_argument(
        "--api-addr",
        default="127.0.0.1",
        help="API 监听地址（默认 127.0.0.1）",
    )
    start_parser.add_argument("--api-port", type=int, default=8899, help="API 端口")
    start_parser.add_argument("--api-token", help="API Token（可通过 API_TOKEN 环境变量指定）")
    start_parser.add_argument("--ssl-cert", help="SSL 证书路径 (PEM)")
    start_parser.add_argument("--ssl-key", help="SSL 私钥路径 (PEM)")
    start_parser.add_argument("--socks-user", help="SOCKS5 用户名（或通过 SOCKS_USER 指定）")
    start_parser.add_argument("--socks-pass", help="SOCKS5 密码（或通过 SOCKS_PASS 指定）")

    subparsers.add_parser("stop", help="停止服务")
    subparsers.add_parser("status", help="查看服务状态")

    proxy_parser = subparsers.add_parser("proxy", help="内部 SOCKS5 工作进程（勿手动调用）")
    proxy_parser.add_argument("--port", type=int, required=True)
    proxy_parser.add_argument("--user", default=None)
    proxy_parser.add_argument("--pass", dest="password", default=None)

    args = parser.parse_args()

    if args.command == "start":
        start_daemon(
            args.api_addr,
            args.api_port,
            args.api_token,
            args.ssl_cert,
            args.ssl_key,
            args.socks_user,
            args.socks_pass,
        )
    elif args.command == "stop":
        stop_daemon()
    elif args.command == "status":
        status_daemon()
    elif args.command == "proxy":
        Socks5Proxy(
            args.port, username=args.user, password=args.password
        ).run()