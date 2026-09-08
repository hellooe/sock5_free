#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOCKS5 节点管理器

Backward-compatible entry point and CLI wrapper for socks5_manager.
"""

from socks5_manager.config import (
    WORK_DIR,
    CONFIG_FILE,
    LOG_DIR,
    TEMPLATE_DIR,
    INDEX_HTML,
    PID_FILE,
    CRED_FILE,
    CHECK_INTERVAL,
    MAX_RETRY,
    CONSECUTIVE_FAILURES,
    VPN_GATE_API,
    HEALTH_CHECK_WORKERS,
    API_CACHE_TTL,
    PROXY_MAX_WORKERS,
    STATE_SAVE_DELAY,
    OVPN_CONNECT_TIMEOUT,
    HEALTH_CURL_TIMEOUT,
    VPNGATE_CACHE_FILE,
    AppConfig,
)
from socks5_manager.logger import setup_logger, get_logger, get_audit_logger
from socks5_manager.utils import (
    _recv_exact,
    check_dependencies,
    is_port_free,
    generate_password,
    load_or_create_credentials,
)
from socks5_manager.models import NodeState
from socks5_manager.state import StateManager
from socks5_manager.vpngate import (
    validate_ovpn,
    fetch_vpngate_nodes,
    get_vpngate_countries,
    get_vpngate_cache_info,
)
from socks5_manager.netns import NetnsManager
from socks5_manager.socks5 import Socks5Proxy
from socks5_manager.node_manager import VpnNodeManager
from socks5_manager.api import APIHandler, create_api_server
from socks5_manager.manager import Manager
from socks5_manager.daemon import daemonize, stop_daemon, status_daemon
from socks5_manager.cli import main

__all__ = [
    "WORK_DIR",
    "CONFIG_FILE",
    "LOG_DIR",
    "TEMPLATE_DIR",
    "INDEX_HTML",
    "PID_FILE",
    "CRED_FILE",
    "CHECK_INTERVAL",
    "MAX_RETRY",
    "CONSECUTIVE_FAILURES",
    "VPN_GATE_API",
    "HEALTH_CHECK_WORKERS",
    "API_CACHE_TTL",
    "PROXY_MAX_WORKERS",
    "STATE_SAVE_DELAY",
    "OVPN_CONNECT_TIMEOUT",
    "HEALTH_CURL_TIMEOUT",
    "VPNGATE_CACHE_FILE",
    "AppConfig",
    "setup_logger",
    "get_logger",
    "get_audit_logger",
    "_recv_exact",
    "check_dependencies",
    "is_port_free",
    "generate_password",
    "load_or_create_credentials",
    "NodeState",
    "StateManager",
    "validate_ovpn",
    "fetch_vpngate_nodes",
    "get_vpngate_countries",
    "get_vpngate_cache_info",
    "NetnsManager",
    "Socks5Proxy",
    "VpnNodeManager",
    "APIHandler",
    "create_api_server",
    "Manager",
    "daemonize",
    "stop_daemon",
    "status_daemon",
    "main",
]

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass