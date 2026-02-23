"""File system watcher for agent workspaces.

Re-exports FileSystemWatcher from parser for backwards compatibility.
Provides a higher-level monitoring loop.
"""

from __future__ import annotations

import logging
import time
from typing import Callable

from watchclaw.models import ActionEvent
from watchclaw.parser import FileSystemWatcher

logger = logging.getLogger(__name__)


class WorkspaceMonitor:
    """High-level workspace monitoring loop."""

    def __init__(
        self,
        watcher: FileSystemWatcher | None = None,
        on_event: Callable[[ActionEvent], None] | None = None,
        poll_interval: float = 2.0,
    ) -> None:
        self.watcher = watcher or FileSystemWatcher(poll_interval=poll_interval)
        self.on_event = on_event
        self.poll_interval = poll_interval
        self._running = False

    def start(self) -> None:
        """Start the monitoring loop (blocking)."""
        logger.info("Starting workspace monitor (poll interval: %.1fs)", self.poll_interval)
        self.watcher.initialize_snapshot()
        self._running = True

        while self._running:
            events = self.watcher.scan()
            if self.on_event:
                for event in events:
                    self.on_event(event)
            time.sleep(self.poll_interval)

    def stop(self) -> None:
        """Stop the monitoring loop."""
        self._running = False
        logger.info("Workspace monitor stopped")
