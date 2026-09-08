#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Thread-safe state manager with debounced JSON persistence and self-healing.
"""

import os
import json
import threading
from typing import Optional, Dict

from .config import CONFIG_FILE, STATE_SAVE_DELAY
from .models import NodeState
from .logger import get_logger, get_audit_logger


class StateManager:
    """Manages node configuration and runtime state persistence."""

    def __init__(self, config_file: str = CONFIG_FILE):
        self.config_file = config_file
        self.nodes: Dict[str, NodeState] = {}
        self._lock = threading.RLock()
        self._dirty = False
        self._save_timer: Optional[threading.Timer] = None
        self._shutdown = False
        self.load()

    def load(self) -> None:
        """Load states from disk, backing up corrupted files if needed."""
        if not os.path.exists(self.config_file):
            return
        logger = get_logger()
        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            fields = set(NodeState.__dataclass_fields__.keys())
            for name, state_data in data.get("nodes", {}).items():
                filtered = {k: v for k, v in state_data.items() if k in fields}
                filtered["running"] = False
                filtered["ext_ip"] = None
                filtered["consecutive_failures"] = 0
                filtered["retry_count"] = 0
                self.nodes[name] = NodeState(**filtered)
            if logger:
                logger.info(f"成功加载 {len(self.nodes)} 个节点状态")
        except json.JSONDecodeError as e:
            if logger:
                logger.error(f"状态文件损坏，备份并重建: {e}")
            backup = self.config_file + ".bak"
            try:
                os.rename(self.config_file, backup)
            except OSError:
                pass
            self.nodes = {}
            self._save_unlocked()
        except Exception as e:
            if logger:
                logger.error(f"加载节点状态失败: {e}")

    def _save_unlocked(self) -> None:
        """Write state to disk atomically without acquiring the lock."""
        data = {"nodes": {name: state.to_persistent_dict() for name, state in self.nodes.items()}}
        tmp_file = self.config_file + ".tmp"
        logger = get_logger()
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.config_file)), exist_ok=True)
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.replace(tmp_file, self.config_file)
            except OSError:
                if os.name == 'nt' and os.path.exists(self.config_file):
                    os.remove(self.config_file)
                    os.replace(tmp_file, self.config_file)
                else:
                    raise
        except OSError as e:
            if logger:
                logger.error(f"保存状态文件失败: {e}")

    def save(self) -> None:
        """Save state to disk immediately."""
        with self._lock:
            self._save_unlocked()

    def mark_dirty(self) -> None:
        """Schedule a debounced save to reduce disk I/O."""
        if self._shutdown:
            return
        with self._lock:
            if self._dirty:
                return
            self._dirty = True
            if self._save_timer is not None:
                self._save_timer.cancel()
            self._save_timer = threading.Timer(STATE_SAVE_DELAY, self._delayed_save)
            self._save_timer.daemon = True
            self._save_timer.start()

    def _delayed_save(self) -> None:
        with self._lock:
            self._save_timer = None
            if not self._dirty:
                return
            self._dirty = False
            self._save_unlocked()

    def close(self) -> None:
        """Flush pending state and prevent new timers."""
        self._shutdown = True
        with self._lock:
            if self._save_timer is not None:
                self._save_timer.cancel()
                self._save_timer = None
            self._save_unlocked()

    def get(self, name: str) -> Optional[NodeState]:
        """Get a node state by name."""
        with self._lock:
            return self.nodes.get(name)

    def add(self, state: NodeState) -> None:
        """Add or overwrite a node state and mark dirty."""
        with self._lock:
            self.nodes[state.name] = state
        self.mark_dirty()
        audit_logger = get_audit_logger()
        if audit_logger:
            audit_logger.info(f"ADD node {state.name} port={state.port} country={state.country}")

    def remove(self, name: str) -> None:
        """Remove a node by name."""
        with self._lock:
            if name in self.nodes:
                del self.nodes[name]
        self.mark_dirty()
        audit_logger = get_audit_logger()
        if audit_logger:
            audit_logger.info(f"REMOVE node {name}")

    def update_runtime(self, name: str, **kwargs) -> None:
        """Update runtime attributes for a node without marking disk dirty."""
        with self._lock:
            if name not in self.nodes:
                return
            node = self.nodes[name]
            for key, value in kwargs.items():
                if hasattr(node, key):
                    setattr(node, key, value)

    def update_ovpn(self, name: str, ovpn_content: str, host_hint: str = "") -> None:
        """Update node's OVPN profile and candidate history, marking disk dirty."""
        with self._lock:
            if name not in self.nodes:
                return
            node = self.nodes[name]
            node.ovpn_content = ovpn_content
            if host_hint:
                node.retry_candidates.append(host_hint)
                if len(node.retry_candidates) > 20:
                    node.retry_candidates = node.retry_candidates[-20:]
        self.mark_dirty()
