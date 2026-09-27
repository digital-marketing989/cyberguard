"""
WebSocket Manager for live Attack Timeline broadcast.
Clients connect to /ws/timeline and receive real-time threat events as JSON.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Dict, List, Any

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages active WebSocket connections and broadcasts events to all clients."""

    def __init__(self):
        self._active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._active.append(ws)
        logger.info("WebSocket client connected. Total: %d", len(self._active))

    def disconnect(self, ws: WebSocket):
        if ws in self._active:
            self._active.remove(ws)
        logger.info("WebSocket client disconnected. Total: %d", len(self._active))

    async def broadcast(self, event: Dict[str, Any]):
        """Send event JSON to all connected clients."""
        if not self._active:
            return
        message = json.dumps(event, default=str)
        disconnected: List[WebSocket] = []
        for ws in self._active:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            self.disconnect(ws)

    async def send_personal(self, ws: WebSocket, event: Dict[str, Any]):
        """Send event to a single client."""
        try:
            await ws.send_text(json.dumps(event, default=str))
        except Exception as exc:
            logger.warning("Failed to send personal WebSocket message: %s", exc)
            self.disconnect(ws)


# ─── Module-level singleton ────────────────────────────────────────────────────
ws_manager = WebSocketManager()
