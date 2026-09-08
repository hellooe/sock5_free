#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Command-line interface (CLI) and daemon lifecycle startup.
"""

import os
import sys
import signal
import threading
import argparse
import subprocess
from typing import Optional

from .config import AppConfig, PID_FILE
from .logger import init_loggers, get_logger
from .utils import check_dependencies, load_or_create_credentials
from .socks5 import Socks5Proxy
from .api import create_api_server
from .manager import Manager
from .daemon import daemonize, get_daemon_pid, stop_daemon, status_daemon


def run_daemon(config: AppConfig, foreground: bool = False) -> None:
    """Validate dependencies, configure credentials, daemonize, and launch services."""
    is_windows = os.name == "nt" or not hasattr(os, "fork")

    if not is_windows:
        missing = check_dependencies()
        if missing:
            print(f"缺少必要命令: {', '.join(missing)}", file=sys.stderr)
            print("请先安装 openvpn / curl / iproute2 / iptables / procps", file=sys.stderr)
            sys.exit(1)

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print("警告: 建议以 root 运行（需要 netns / iptables 权限）", file=sys.stderr)
    else:
        print("[开发测试模式] 检测到当前操作系统为 Windows，已跳过 Linux netns/iptables 命令检测")
        foreground = True  # Windows 始终前台运行

    api_token = config.api_token or os.environ.get("API_TOKEN")
    if not api_token:
        if is_windows:
            api_token = "dev"
            print("[开发测试模式] API Token 未指定，已自动使用默认 Token: dev")
        else:
            print("错误: 必须提供 --api-token 或设置 API_TOKEN 环境变量", file=sys.stderr)
            sys.exit(1)
    config.api_token = api_token

    socks_user = config.socks_user or os.environ.get("SOCKS_USER")
    socks_pass = config.socks_pass or os.environ.get("SOCKS_PASS")
    config.socks_user, config.socks_pass = load_or_create_credentials(socks_user, socks_pass)

    print(f"SOCKS5 认证用户: {config.socks_user}")
    print(f"SOCKS5 认证密码: {'*' * len(config.socks_pass) if config.socks_pass else '(无)'}")
    print("请妥善保管，也可在 Web 控制台查看")

    if not is_windows and not foreground and get_daemon_pid(PID_FILE):
        print("后台进程已经在运行中")
        return

    if not is_windows:
        # Enable kernel IP forwarding
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
        if not foreground:
            daemonize(PID_FILE)
        else:
            print(f"前台模式运行服务: http://{config.api_addr}:{config.api_port}")
            print("按 Ctrl+C 可停止服务")
    else:
        print(f"[开发测试模式] 正在本地前台运行服务: http://{config.api_addr}:{config.api_port}")
        print("[开发测试模式] 按 Ctrl+C 可停止服务")

    config.ensure_directories()
    init_loggers()
    logger = get_logger()

    manager = Manager(config=config)
    shutdown_event = threading.Event()

    def sig_handler(signum, frame):
        if logger:
            logger.info("收到退出信号，开始优雅关闭...")
        shutdown_event.set()

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, sig_handler)
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, sig_handler)

    server = create_api_server(manager, config)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    if logger:
        logger.info(
            f"API/Web 服务就绪: {config.api_addr}:{config.api_port} "
            f"(SSL={'yes' if config.ssl_cert else 'no'})"
        )
        logger.info(f"SOCKS 认证已启用: user={config.socks_user}")

    manager.start_all()
    try:
        manager.run_health_loop(shutdown_event=shutdown_event)
    finally:
        manager.close()
        try:
            server.shutdown()
        except Exception:
            pass


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
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
    start_parser.add_argument(
        "--foreground", "-f",
        action="store_true",
        default=False,
        help="前台运行（不守护进程化，适用于 systemd / Docker）",
    )

    subparsers.add_parser("stop", help="停止服务")
    subparsers.add_parser("status", help="查看服务状态")

    proxy_parser = subparsers.add_parser("proxy", help="内部 SOCKS5 工作进程（勿手动调用）")
    proxy_parser.add_argument("--port", type=int, required=True)
    proxy_parser.add_argument("--user", default=None)
    proxy_parser.add_argument("--pass", dest="password", default=None)

    return parser


def main(args: Optional[list] = None) -> None:
    """CLI entry point dispatch."""
    parser = build_parser()
    parsed = parser.parse_args(args)

    if parsed.command == "start":
        config = AppConfig(
            api_addr=parsed.api_addr,
            api_port=parsed.api_port,
            api_token=parsed.api_token,
            ssl_cert=parsed.ssl_cert,
            ssl_key=parsed.ssl_key,
            socks_user=parsed.socks_user,
            socks_pass=parsed.socks_pass,
        )
        run_daemon(config, foreground=parsed.foreground)
    elif parsed.command == "stop":
        stop_daemon()
    elif parsed.command == "status":
        status_daemon()
    elif parsed.command == "proxy":
        username = parsed.user or os.environ.get("SOCKS_USER")
        password = parsed.password or os.environ.get("SOCKS_PASS")
        Socks5Proxy(
            parsed.port, username=username, password=password
        ).run()


if __name__ == "__main__":
    main()
