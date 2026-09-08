#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux Network Namespace (netns), veth pair, and iptables NAT manager.
"""

import os
import shutil
import hashlib
import threading
import subprocess
from typing import Optional, Dict

from .logger import get_logger


class NetnsManager:
    """Manages creation, routing, and destruction of network namespaces and NAT rules."""

    def __init__(self):
        self.allocated_subnets: Dict[str, int] = {}
        self._lock = threading.Lock()

    @staticmethod
    def get_netns_name(name: str) -> str:
        """Generate deterministic and safe namespace name."""
        safe = hashlib.md5(name.encode()).hexdigest()[:10]
        return f"vpn-{safe}"

    def allocate_subnet_id(self, name: str) -> int:
        """Allocate a unique /24 subnet index (10-249) for the node."""
        with self._lock:
            if name in self.allocated_subnets:
                return self.allocated_subnets[name]
            used = set(self.allocated_subnets.values())
            for sub_id in range(10, 250):
                if sub_id not in used:
                    self.allocated_subnets[name] = sub_id
                    return sub_id
            raise RuntimeError("没有可用的 CIDR 子网网段（最大支持 240 个并发节点）")

    def release_subnet_id(self, name: str) -> None:
        """Release allocated subnet ID for node."""
        with self._lock:
            self.allocated_subnets.pop(name, None)

    def setup_netns(self, name: str, port: int) -> bool:
        """Create and configure netns, veth interface pair, routing, and iptables DNAT/MASQUERADE."""
        logger = get_logger()
        netns = self.get_netns_name(name)
        name_hash = hashlib.md5(name.encode()).hexdigest()[:8]
        veth_host = f"vh-{name_hash}"
        veth_ns = f"vn-{name_hash}"

        self.cleanup_netns(name, port)
        sub_id = self.allocate_subnet_id(name)
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

            check_pre = subprocess.run(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-C",
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
                capture_output=True,
                check=False,
            )
            if check_pre.returncode != 0:
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

            check_out = subprocess.run(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-C",
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
                capture_output=True,
                check=False,
            )
            if check_out.returncode != 0:
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
            self.cleanup_netns(name, port)
            return False

    def cleanup_netns(self, name: str, port: Optional[int] = None) -> None:
        """Remove netns, veth interface pair, iptables rules, and release subnet."""
        netns = self.get_netns_name(name)
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
                timeout=5,
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
                    timeout=5,
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
                    timeout=5,
                )

        subprocess.run(
            ["ip", "link", "del", veth_host], stderr=subprocess.DEVNULL, check=False, timeout=5
        )
        subprocess.run(
            ["ip", "netns", "del", netns], stderr=subprocess.DEVNULL, check=False, timeout=5
        )

        netns_dns_dir = f"/etc/netns/{netns}"
        if os.path.exists(netns_dns_dir):
            try:
                shutil.rmtree(netns_dns_dir)
            except OSError:
                pass
        self.release_subnet_id(name)
