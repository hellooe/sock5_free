#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP REST API and Web Console server for SOCKS5 Node Manager.
"""

import os
import json
import time
import ssl
import secrets
import re
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional, List, Dict, Any

from .config import INDEX_HTML, AppConfig
from .models import NodeState
from .utils import is_port_free
from .vpngate import (
    validate_ovpn,
    fetch_vpngate_nodes,
    get_vpngate_node_by_host,
    get_vpngate_nodes_summary,
    get_vpngate_countries,
    get_vpngate_cache_info,
)
from .logger import get_logger


class APIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for API endpoints and Web dashboard."""
    manager: Any = None
    config: Optional[AppConfig] = None

    def log_message(self, format: str, *args) -> None:
        logger = get_logger()
        if logger:
            logger.debug("%s - %s", self.address_string(), format % args)

    def _check_auth(self) -> bool:
        expected_token = self.config.api_token if self.config else None
        token = self.headers.get("X-API-Token")
        if not expected_token or not token or not secrets.compare_digest(token, expected_token):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(b'{"error":"Unauthorized"}')
            return False
        return True

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/", "/index.html"):
            self.send_html()
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
                    "socks_user": self.config.socks_user if self.config else None,
                    "socks_pass": self.config.socks_pass if self.config else None,
                }
            )
        elif path == "/api/vpngate/nodes":
            params = parse_qs(parsed.query)
            force_refresh = (
                params.get("refresh", ["0"])[0] in ("1", "true", "yes")
                or params.get("force", ["0"])[0] in ("1", "true", "yes")
            )
            country = params.get("country", [None])[0]
            if country == "":
                country = None
            nodes = get_vpngate_nodes_summary(country=country, force_refresh=force_refresh)
            self.send_json(nodes)
        elif path == "/api/vpngate/countries":
            self.send_json(get_vpngate_countries())
        elif path == "/api/vpngate/cache":
            self.send_json(get_vpngate_cache_info())
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
        logger = get_logger()
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
            # 1. Determine OVPN content and country
            if "vpngate_host" in data and data["vpngate_host"]:
                vpngate_host = str(data["vpngate_host"]).strip()
                node_info = get_vpngate_node_by_host(vpngate_host)
                if not node_info:
                    self.send_json({"error": f"未找到指定的 VPN Gate 节点 ({vpngate_host})，请刷新列表重试"}, 400)
                    return
                ovpn = node_info["ovpn"]
                country = node_info.get("country", "")
                default_name = f"{country}_{vpngate_host.split('.')[0]}_{int(time.time()) % 10000}"
            elif "country" in data and data["country"]:
                nodes = fetch_vpngate_nodes(data["country"])
                if not nodes:
                    self.send_json({"error": "未获取到该国家可用的节点"}, 400)
                    return
                ovpn = nodes[0]["ovpn"]
                country = nodes[0]["country"]
                default_name = f"{country}_{int(time.time())}"
            else:
                ovpn = data.get("ovpn_content")
                if not ovpn or not isinstance(ovpn, str):
                    self.send_json({"error": "缺少 ovpn_content, country 或 vpngate_host"}, 400)
                    return
                ok, msg = validate_ovpn(ovpn)
                if not ok:
                    self.send_json({"error": f"ovpn 校验失败: {msg}"}, 400)
                    return
                country = data.get("country")
                default_name = f"node_{int(time.time())}"

            # 2. Determine node name
            name = data.get("name") or default_name
            if not isinstance(name, str) or not name.strip():
                self.send_json({"error": "节点名称无效"}, 400)
                return
            name = name.strip()[:64]
            if not re.match(r'^[a-zA-Z0-9_\-]+$', name):
                self.send_json({"error": "节点名称只允许字母、数字、下划线和短横线"}, 400)
                return

            if name in self.manager.state_mgr.nodes:
                self.send_json({"error": f'节点 "{name}" 已存在'}, 400)
                return

            # 3. Determine and validate port
            port = data.get("port")
            if port is not None and port != "":
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

    def _get_nodes(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self.manager.state_mgr.nodes.values()]

    def _get_status(self) -> Dict[str, Any]:
        has_auth = bool(self.config and self.config.socks_user and self.config.socks_pass)
        cache_info = get_vpngate_cache_info()
        return {
            "total": len(self.manager.state_mgr.nodes),
            "running": sum(1 for s in self.manager.state_mgr.nodes.values() if s.running),
            "socks_auth_enabled": has_auth,
            "vpngate_cache_file": cache_info["cache_file"],
            "vpngate_cached_at": cache_info["cache_time_str"],
        }

    def _get_free_port(self) -> Optional[int]:
        used = {s.port for s in self.manager.state_mgr.nodes.values()}
        for port in range(10801, 12000):
            if port not in used and is_port_free(port):
                return port
        return None

    def send_json(self, obj: Any, status: int = 200) -> None:
        """Send JSON response with nosniff security header."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def send_html(self, template_path: Optional[str] = None) -> None:
        """Serve the Web dashboard HTML template from disk."""
        candidates = [
            template_path,
            INDEX_HTML,
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates", "index.html"),
        ]
        chosen = None
        for cand in candidates:
            if cand and os.path.exists(cand):
                chosen = cand
                break

        if not chosen:
            self.send_error(404, "Template Not Found")
            return

        try:
            with open(chosen, "rb") as f:
                html = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(html)
        except OSError:
            self.send_error(404)


def create_api_server(
    manager: Any,
    config: AppConfig,
) -> HTTPServer:
    """Create configured HTTPServer instance with optional TLS/SSL."""
    APIHandler.manager = manager
    APIHandler.config = config
    server = ThreadingHTTPServer((config.api_addr, config.api_port), APIHandler)
    if config.ssl_cert and config.ssl_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(config.ssl_cert, config.ssl_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server
