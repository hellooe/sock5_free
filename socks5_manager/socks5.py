#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
High-performance SOCKS5 Proxy Server supporting RFC 1928 and RFC 1929 authentication.
"""

import socket
import struct
import select
import secrets
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

from .config import PROXY_MAX_WORKERS
from .utils import _recv_exact
from .logger import get_logger


class Socks5Proxy:
    """SOCKS5 proxy server supporting IPv4, IPv6, Domain names, and Username/Password auth."""

    def __init__(
        self,
        port: int,
        username: Optional[str] = None,
        password: Optional[str] = None,
        max_workers: int = PROXY_MAX_WORKERS,
    ):
        self.port = port
        self.username = username
        self.password = password
        self.require_auth = bool(username and password)
        self.running = True
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="socks"
        )
        self._server_socket: Optional[socket.socket] = None

    def _forward(self, conn: socket.socket, target: socket.socket) -> None:
        """Bidirectionally relay traffic between client and destination target."""
        try:
            conn_open = True
            target_open = True
            while self.running and (conn_open or target_open):
                readable = []
                if conn_open:
                    readable.append(conn)
                if target_open:
                    readable.append(target)
                if not readable:
                    break
                r, _, _ = select.select(readable, [], [], 1.0)
                if not r:
                    continue
                if conn in r:
                    data = conn.recv(8192)
                    if not data:
                        conn_open = False
                        try:
                            target.shutdown(socket.SHUT_WR)
                        except Exception:
                            pass
                    else:
                        target.sendall(data)
                if target in r:
                    data = target.recv(8192)
                    if not data:
                        target_open = False
                        try:
                            conn.shutdown(socket.SHUT_WR)
                        except Exception:
                            pass
                    else:
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
        """Handle individual SOCKS5 client negotiation and proxying."""
        target: Optional[socket.socket] = None
        try:
            # 1. Negotiation Greeting
            header = _recv_exact(conn, 2)
            if not header or header[0] != 5:
                return
            nmethods = header[1]
            methods = _recv_exact(conn, nmethods)
            if methods is None:
                return

            # 2. Authentication selection
            if self.require_auth:
                if 2 not in methods:
                    conn.sendall(b"\x05\xff")  # No acceptable methods
                    return
                conn.sendall(b"\x05\x02")  # Username/Password auth

                # RFC 1929 sub-negotiation
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
                    not secrets.compare_digest(
                        uname.decode("utf-8", errors="ignore"), self.username
                    )
                    or not secrets.compare_digest(
                        passwd.decode("utf-8", errors="ignore"), self.password
                    )
                ):
                    conn.sendall(b"\x01\x01")  # Auth failure
                    return
                conn.sendall(b"\x01\x00")  # Auth success
            else:
                if 0 not in methods:
                    conn.sendall(b"\x05\xff")
                    return
                conn.sendall(b"\x05\x00")  # No authentication required

            # 3. Request Details
            req = _recv_exact(conn, 4)
            if not req or req[0] != 5:
                return
            if req[1] != 1:  # Only CONNECT (CMD=1) is supported
                conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")  # Command not supported
                return

            addr_type = req[3]
            if addr_type == 1:  # IPv4
                raw_ip = _recv_exact(conn, 4)
                if not raw_ip:
                    return
                addr = socket.inet_ntoa(raw_ip)
            elif addr_type == 3:  # Domain name
                raw_len = _recv_exact(conn, 1)
                if not raw_len:
                    return
                domain_len = raw_len[0]
                raw_domain = _recv_exact(conn, domain_len)
                if not raw_domain:
                    return
                addr = raw_domain.decode("utf-8", errors="ignore")
            elif addr_type == 4:  # IPv6
                raw_ip6 = _recv_exact(conn, 16)
                if not raw_ip6:
                    return
                addr = socket.inet_ntop(socket.AF_INET6, raw_ip6)
            else:
                conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")  # Address type not supported
                return

            raw_port = _recv_exact(conn, 2)
            if not raw_port:
                return
            port = struct.unpack(">H", raw_port)[0]

            # 4. Connect to upstream target
            try:
                target = socket.create_connection((addr, port), timeout=12)
            except Exception:
                conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")  # Connection refused
                return

            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")  # Success reply
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            target.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            conn.settimeout(None)
            target.settimeout(None)

            # 5. Begin full duplex forwarding
            self._forward(conn, target)
        except Exception:
            pass
        finally:
            if target is not None:
                try:
                    target.close()
                except Exception:
                    pass
            try:
                conn.close()
            except Exception:
                pass

    def stop(self) -> None:
        """Stop proxy server and terminate connections."""
        self.running = False
        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except Exception:
                pass
        self.executor.shutdown(wait=False, cancel_futures=True)

    def run(self) -> None:
        """Bind server socket and accept client connections."""
        logger = get_logger()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", self.port))
        except OSError as e:
            if logger:
                logger.error(f"代理绑定端口 {self.port} 失败: {e}")
            server.close()
            return
        server.listen(256)
        server.settimeout(1.0)
        self._server_socket = server

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
            self.stop()
