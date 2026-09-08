#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unix daemonization, process control, and PID file management.
"""

import errno
import os
import sys
import time
import signal
import atexit
from typing import Optional

from .config import PID_FILE


def daemonize(pid_file: str = PID_FILE) -> None:
    """Detach process into background daemon (Linux/Unix only)."""
    if not hasattr(os, "fork"):
        print("当前操作系统不支持 fork 守护进程模式（仅支持 Linux / Unix 系统）", file=sys.stderr)
        return

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
    if hasattr(os, "umask"):
        os.umask(0o027)

    os.makedirs(os.path.dirname(os.path.abspath(pid_file)), exist_ok=True)
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))
    atexit.register(
        lambda: os.remove(pid_file) if os.path.exists(pid_file) else None
    )


def get_daemon_pid(pid_file: str = PID_FILE) -> Optional[int]:
    """Read the PID of currently running daemon if present."""
    if not os.path.exists(pid_file):
        return None
    try:
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


def stop_daemon(pid_file: str = PID_FILE) -> None:
    """Send SIGTERM to running daemon process and await termination."""
    pid = get_daemon_pid(pid_file)
    if not pid:
        print("服务尚未运行")
        return
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            time.sleep(0.3)
            try:
                os.kill(pid, 0)
            except OSError:
                break
        else:
            # Process still alive after 6s, escalate to SIGKILL
            print("进程未响应 SIGTERM，发送 SIGKILL...")
            try:
                os.kill(pid, signal.SIGKILL)
                time.sleep(0.5)
            except OSError:
                pass
        # Clean up PID file
        if os.path.exists(pid_file):
            try:
                os.remove(pid_file)
            except OSError:
                pass
        print("服务已停止")
    except Exception as e:
        print(f"停止服务失败: {e}")


def status_daemon(pid_file: str = PID_FILE) -> None:
    """Print whether the daemon process is running and its PID."""
    pid = get_daemon_pid(pid_file)
    if pid:
        print(f"守护服务运行中，PID: {pid}")
    else:
        print("服务尚未运行")
