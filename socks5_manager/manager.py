#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Coordinator (Manager) orchestrating StateManager, VpnNodeManager, and health loop.
"""

import time
from typing import Optional

from .config import CONFIG_FILE, CHECK_INTERVAL, AppConfig
from .state import StateManager
from .node_manager import VpnNodeManager
from .logger import get_logger


class Manager:
    """Central coordinator for managing node state, network lifecycle, and health checking."""

    def __init__(
        self,
        config: Optional[AppConfig] = None,
        config_file: str = CONFIG_FILE,
    ):
        self.config = config or AppConfig()
        self.state_mgr = StateManager(config_file)
        self.node_mgr = VpnNodeManager(self.state_mgr, config=self.config)

    def start_all(self) -> None:
        """Start all configured nodes that are not currently running."""
        logger = get_logger()
        for name, state in list(self.state_mgr.nodes.items()):
            if not state.running:
                if logger:
                    logger.info(f"启动已配置节点: {name}")
                self.node_mgr.start_node(name)

    def stop_all(self) -> None:
        """Stop all running nodes and clean up namespaces."""
        for name in list(self.state_mgr.nodes.keys()):
            self.node_mgr.stop_node(name)

    def run_health_loop(self, shutdown_event=None) -> None:
        """Continuously run periodic health checks across nodes."""
        logger = get_logger()
        while not (shutdown_event and shutdown_event.is_set()):
            try:
                self.node_mgr.health_check()
            except Exception as e:
                if logger:
                    logger.error(f"健康检查循环异常: {e}")
            if shutdown_event and shutdown_event.wait(CHECK_INTERVAL):
                break
            elif not shutdown_event:
                time.sleep(CHECK_INTERVAL)

    def close(self) -> None:
        """Gracefully stop all nodes and flush pending state."""
        logger = get_logger()
        if logger:
            logger.info("正在关闭所有节点与资源...")
        self.stop_all()
        self.node_mgr.close()
        self.state_mgr.close()
