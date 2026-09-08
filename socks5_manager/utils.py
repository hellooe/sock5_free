#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Common utilities: socket helpers, port checking, dependency checks, credentials.
"""

import os
import sys
import json
import socket
import shutil
import secrets
import string
from typing import Optional, List, Tuple

from .config import WORK_DIR, CRED_FILE


def _recv_exact(conn: socket.socket, n: int) -> Optional[bytes]:
    """Read exactly n bytes from a socket, or return None if connection closes/errors."""
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
    """Check for required external system commands."""
    required = ["openvpn", "curl", "ip", "iptables", "pkill"]
    return [cmd for cmd in required if shutil.which(cmd) is None]


def is_port_free(port: int, host: str = "0.0.0.0") -> bool:
    """Check if a TCP port is available to bind."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False


def generate_password(length: int = 16) -> str:
    """Generate a cryptographically secure random alphanumeric password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def load_or_create_credentials(
    user_override: Optional[str] = None,
    pass_override: Optional[str] = None,
    cred_file: str = CRED_FILE,
) -> Tuple[str, str]:
    """Load existing SOCKS5 credentials or generate and persist new ones."""
    if user_override and pass_override:
        return user_override, pass_override

    user = "socks"
    passwd = None

    if os.path.exists(cred_file):
        try:
            with open(cred_file, "r", encoding="utf-8") as f:
                cred = json.load(f)
            user = cred.get("user") or "socks"
            passwd = cred.get("pass")
        except Exception:
            pass

    if not passwd:
        passwd = generate_password()

    if user_override:
        user = user_override
    if pass_override:
        passwd = pass_override

    try:
        os.makedirs(os.path.dirname(cred_file), exist_ok=True)
        with open(cred_file, "w", encoding="utf-8") as f:
            json.dump({"user": user, "pass": passwd}, f, indent=2)
        if hasattr(os, "chmod"):
            try:
                os.chmod(cred_file, 0o600)
            except OSError:
                pass
    except OSError as e:
        print(f"无法保存凭证文件: {e}", file=sys.stderr)

    return user, passwd
