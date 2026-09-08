#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data models for SOCKS5 Node Manager.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class NodeState:
    """Representation of a managed VPN/SOCKS5 node and its runtime state."""
    name: str
    port: int
    country: Optional[str]
    ovpn_content: str
    ext_ip: Optional[str] = None
    consecutive_failures: int = 0
    running: bool = False
    retry_count: int = 0
    retry_candidates: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not isinstance(self.port, int) or not (1024 <= self.port <= 65535):
            raise ValueError(f"无效端口: {self.port}，范围必须为 1024-65535")
        if not self.name or not re.match(r'^[a-zA-Z0-9_\-]+$', self.name):
            raise ValueError(f"无效节点名称: {self.name}，只允许字母、数字、下划线和短横线")

    def to_dict(self) -> Dict[str, Any]:
        """Convert full state to dictionary for API presentation."""
        return {
            "name": self.name,
            "port": self.port,
            "country": self.country,
            "running": self.running,
            "ext_ip": self.ext_ip,
            "failures": self.consecutive_failures,
        }

    def to_persistent_dict(self) -> Dict[str, Any]:
        """Convert state to persistent dictionary for state.json."""
        return {
            "name": self.name,
            "port": self.port,
            "country": self.country,
            "ovpn_content": self.ovpn_content,
            "retry_candidates": self.retry_candidates,
        }
