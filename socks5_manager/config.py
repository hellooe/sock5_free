#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration and constants for SOCKS5 Node Manager.
"""

import os
from dataclasses import dataclass
from typing import Optional

# Base directories and file paths (all inside the project directory)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK_DIR = os.environ.get("SOCKS5_WORK_DIR", PROJECT_ROOT)
CONFIG_FILE = os.path.join(WORK_DIR, "state.json")
LOG_DIR = os.path.join(WORK_DIR, "logs")
TEMPLATE_DIR = os.path.join(PROJECT_ROOT, "templates")
INDEX_HTML = os.path.join(TEMPLATE_DIR, "index.html")
PID_FILE = os.path.join(WORK_DIR, "daemon.pid")
CRED_FILE = os.path.join(WORK_DIR, "socks_credentials.json")
VPNGATE_CACHE_FILE = os.environ.get("SOCKS5_VPNGATE_CACHE_FILE", os.path.join(WORK_DIR, "vpngate_cache.json"))

# Operational defaults
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


@dataclass
class AppConfig:
    """Runtime configuration for daemon and services."""
    api_addr: str = "127.0.0.1"
    api_port: int = 8899
    api_token: Optional[str] = None
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    socks_user: Optional[str] = None
    socks_pass: Optional[str] = None

    def ensure_directories(self) -> None:
        """Create required runtime directories."""
        import stat
        mode = 0o700 if os.name != 'nt' else 0o755
        os.makedirs(WORK_DIR, mode=mode, exist_ok=True)
        os.makedirs(LOG_DIR, mode=mode, exist_ok=True)
        os.makedirs(TEMPLATE_DIR, exist_ok=True)
