#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Logging facility with non-blocking queue handlers.
"""

import os
import sys
import queue
import logging
from logging.handlers import RotatingFileHandler, QueueHandler, QueueListener
from typing import Optional

from .config import LOG_DIR

_main_logger: Optional[logging.Logger] = None
_audit_logger: Optional[logging.Logger] = None
_listeners = []


def setup_logger(name: str, log_dir: str = LOG_DIR) -> logging.Logger:
    """Configure a logger with a rotating file queue listener and console handler."""
    lg = logging.getLogger(name)
    if lg.handlers:
        return lg
    lg.setLevel(logging.INFO)
    os.makedirs(log_dir, exist_ok=True)

    fh = RotatingFileHandler(
        os.path.join(log_dir, f"{name}.log"),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    fh.setFormatter(formatter)

    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(formatter)

    log_queue: queue.Queue = queue.Queue(-1)
    qh = QueueHandler(log_queue)
    lg.addHandler(qh)

    listener = QueueListener(log_queue, fh, sh)
    listener.start()
    _listeners.append(listener)
    return lg


def init_loggers() -> None:
    """Initialize standard loggers for the application."""
    global _main_logger, _audit_logger
    _main_logger = setup_logger("socks5vpn")
    _audit_logger = setup_logger("audit")


def get_logger() -> logging.Logger:
    """Get the main application logger."""
    global _main_logger
    if _main_logger is None:
        _main_logger = setup_logger("socks5vpn")
    return _main_logger


def get_audit_logger() -> logging.Logger:
    """Get the audit logger for security-relevant operations."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = setup_logger("audit")
    return _audit_logger
