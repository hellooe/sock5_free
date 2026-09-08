#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN node and proxy process lifecycle, health monitoring, and automated failover.
"""

import os
import sys
import time
import threading
import subprocess
import ipaddress
from typing import Optional, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError

from .config import (
    WORK_DIR,
    LOG_DIR,
    PROJECT_ROOT,
    CHECK_INTERVAL,
    MAX_RETRY,
    CONSECUTIVE_FAILURES,
    HEALTH_CHECK_WORKERS,
    OVPN_CONNECT_TIMEOUT,
    HEALTH_CURL_TIMEOUT,
    AppConfig,
)
from .state import StateManager
from .netns import NetnsManager
from .vpngate import fetch_vpngate_nodes
from .logger import get_logger, get_audit_logger


class VpnNodeManager:
    """Manages OpenVPN tunnels, SOCKS5 workers, and health failover across network namespaces."""

    def __init__(
        self,
        state_mgr: StateManager,
        netns_mgr: Optional[NetnsManager] = None,
        config: Optional[AppConfig] = None,
    ):
        self.state_mgr = state_mgr
        self.netns_mgr = netns_mgr or NetnsManager()
        self.config = config or AppConfig()
        self.ovpn_processes: Dict[str, subprocess.Popen] = {}
        self.proxy_processes: Dict[str, subprocess.Popen] = {}
        self.health_executor = ThreadPoolExecutor(
            max_workers=HEALTH_CHECK_WORKERS, thread_name_prefix="health"
        )
        self.restart_executor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="restart"
        )
        self.restarting_nodes: Set[str] = set()
        self._lock = threading.Lock()

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
                    try:
                        ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    else:
                        return ip
            except Exception:
                continue
        return None

    def _probe_via_socks(self, port: int) -> Optional[str]:
        endpoints = ["ifconfig.me", "api.ipify.org", "icanhazip.com"]
        auth = (
            f"{self.config.socks_user}:{self.config.socks_pass}"
            if self.config.socks_user and self.config.socks_pass
            else None
        )
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
                    try:
                        ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    else:
                        return ip
            except Exception:
                continue
        return None

    def start_node(self, name: str) -> bool:
        """Start OpenVPN tunnel and SOCKS5 proxy in dedicated netns."""
        logger = get_logger()
        audit_logger = get_audit_logger()
        state = self.state_mgr.get(name)
        if not state:
            if logger:
                logger.error(f"节点 {name} 不存在")
            return False

        if os.name == "nt":
            ext_ip = "127.0.0.1"
            for line in state.ovpn_content.splitlines():
                line = line.strip()
                if line.startswith("remote "):
                    parts = line.split()
                    if len(parts) >= 2:
                        ext_ip = parts[1]
                        break
            self.state_mgr.update_runtime(
                name,
                running=True,
                ext_ip=ext_ip,
                consecutive_failures=0,
                retry_count=0,
            )
            if logger:
                logger.info(f"[Windows开发测试] 节点 {name} 模拟启动成功，出口 IP: {ext_ip}，端口: {state.port}")
            if audit_logger:
                audit_logger.info(f"START node {name} port={state.port} ext_ip={ext_ip}")
            return True

        with self._lock:
            if name in self.ovpn_processes or name in self.proxy_processes:
                if logger:
                    logger.warning(f"节点 {name} 已有进程在运行，先清理")
                self.stop_node(name)

        netns = self.netns_mgr.get_netns_name(name)
        if not self.netns_mgr.setup_netns(name, state.port):
            return False

        ovpn_file = self._get_ovpn_file(name)
        try:
            with open(ovpn_file, "w", encoding="utf-8") as f:
                f.write(state.ovpn_content)
        except OSError as e:
            if logger:
                logger.error(f"写入 ovpn 文件失败: {e}")
            self.netns_mgr.cleanup_netns(name, state.port)
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
            self.netns_mgr.cleanup_netns(name, state.port)
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
                logger.error(f"节点 {name} 建立 VPN 隧道超时（{OVPN_CONNECT_TIMEOUT}s），中止启动")
            self.stop_node(name)
            return False
        else:
            if logger:
                logger.info(f"节点 {name} 隧道就绪，出口 IP: {ext_ip}")

        # Resolve script path for proxy execution inside netns
        entry_script = os.path.abspath(sys.argv[0]) if sys.argv and os.path.isfile(sys.argv[0]) else os.path.join(PROJECT_ROOT, "socks5_free.py")
        proxy_cmd = [
            "ip",
            "netns",
            "exec",
            netns,
            sys.executable,
            entry_script,
            "proxy",
            "--port",
            str(state.port),
        ]
        
        proxy_env = os.environ.copy()
        if self.config.socks_user and self.config.socks_pass:
            proxy_env["SOCKS_USER"] = self.config.socks_user
            proxy_env["SOCKS_PASS"] = self.config.socks_pass

        try:
            proxy_log_path = os.path.join(LOG_DIR, f"proxy-{name}.log")
            with open(proxy_log_path, "a", encoding="utf-8") as proxy_log:
                proxy_proc = subprocess.Popen(
                    proxy_cmd,
                    stdout=proxy_log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    env=proxy_env,
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
        """Stop OpenVPN and proxy processes, and clean up network namespace."""
        logger = get_logger()
        audit_logger = get_audit_logger()
        state = self.state_mgr.get(name)
        port = state.port if state else None

        if os.name == "nt":
            self.state_mgr.update_runtime(name, running=False, ext_ip=None)
            if logger:
                logger.info(f"[Windows开发测试] 节点 {name} 模拟停止并清理")
            if audit_logger:
                audit_logger.info(f"STOP node {name}")
            return

        netns = self.netns_mgr.get_netns_name(name)

        subprocess.run(
            ["ip", "netns", "exec", netns, "pkill", "-9", "-f", "openvpn"],
            stderr=subprocess.DEVNULL,
            check=False,
        )
        subprocess.run(
            ["ip", "netns", "exec", netns, "pkill", "-9", "-f", "proxy"],
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

        self.netns_mgr.cleanup_netns(name, port)
        self.state_mgr.update_runtime(name, running=False, ext_ip=None)
        if logger:
            logger.info(f"节点 {name} 已停止并清理")
        if audit_logger:
            audit_logger.info(f"STOP node {name}")

    def health_check(self) -> None:
        """Perform concurrent health checks across all active nodes."""
        logger = get_logger()
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

        if os.name == "nt":
            return state.ext_ip or "127.0.0.1"

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
        logger = get_logger()
        audit_logger = get_audit_logger()
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
        """Stop all processes and shut down thread executors."""
        with self._lock:
            nodes_to_stop = set(list(self.ovpn_processes.keys()) + list(self.proxy_processes.keys()))
        for name in nodes_to_stop:
            try:
                self.stop_node(name)
            except Exception:
                pass
        self.health_executor.shutdown(wait=False, cancel_futures=True)
        self.restart_executor.shutdown(wait=False, cancel_futures=True)
