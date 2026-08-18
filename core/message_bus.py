"""
Asynchronous event and streaming message bus for inter-agent communication & WebSockets.
"""

import asyncio
import json
import logging
from collections import deque
from typing import Dict, List, Callable, Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger("CyberAgent.MessageBus")


class AgentEvent:
    def __init__(
        self,
        event_type: str,
        agent_id: str,
        agent_name: str,
        payload: Dict[str, Any],
        step_index: int = 0,
        total_steps: int = 1,
    ):
        self.event_type = event_type  # 'start', 'stream', 'thinking', 'tool_call', 'complete', 'error', 'gpu_update'
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.payload = payload
        self.step_index = step_index
        self.total_steps = total_steps
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.event_type,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "payload": self.payload,
            "step_index": self.step_index,
            "total_steps": self.total_steps,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class MessageBus:
    """Async pub/sub message bus for live agent streaming and UI events."""

    def __init__(self):
        self._subscribers: List[asyncio.Queue] = []
        self._callbacks: List[Callable[[AgentEvent], None]] = []
        self._history: deque = deque(maxlen=200)  # ring-buffer of last 200 events
        self._loop: Optional[asyncio.AbstractEventLoop] = None  # captured from async context

    def subscribe(self) -> asyncio.Queue:
        """Register a new queue listener (e.g. WebSocket connection)."""
        # Capture the running event loop from the async WebSocket context
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                pass
        queue = asyncio.Queue()
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        """Remove a queue listener."""
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    def register_callback(self, callback: Callable[[AgentEvent], None]):
        """Register synchronous callback function."""
        self._callbacks.append(callback)

    def unregister_callback(self, callback: Callable[[AgentEvent], None]):
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    async def emit(self, event: AgentEvent):
        """Publish an event to all subscribers and callbacks."""
        # Capture the running loop the first time we are called from async context
        if self._loop is None:
            self._loop = asyncio.get_running_loop()

        # Store in history ring-buffer
        self._history.append(event.to_dict())

        # Execute callbacks
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception as e:
                logger.error(f"Callback error: {e}")

        # Broadcast to async queues
        dead_queues = []
        for q in self._subscribers:
            try:
                await q.put(event)
            except Exception:
                dead_queues.append(q)

        for dq in dead_queues:
            self.unsubscribe(dq)

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent `limit` events from the history buffer."""
        history = list(self._history)
        return history[-limit:] if len(history) > limit else history

    def emit_sync(self, event: AgentEvent):
        """Synchronous emit helper — thread-safe for use inside run_in_executor."""
        # Store in history immediately (sync-safe)
        self._history.append(event.to_dict())

        # Fire synchronous callbacks
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception as e:
                logger.error(f"Sync callback error: {e}")

        # Broadcast to async WebSocket queues using the captured event loop
        if self._loop is not None and self._loop.is_running():
            try:
                asyncio.run_coroutine_threadsafe(self._broadcast(event), self._loop)
            except Exception:
                pass

    async def _broadcast(self, event: AgentEvent):
        """Internal: push event to all subscriber queues (runs on the main event loop)."""
        dead_queues = []
        for q in self._subscribers:
            try:
                await q.put(event)
            except Exception:
                dead_queues.append(q)
        for dq in dead_queues:
            self.unsubscribe(dq)


# Global message bus singleton
message_bus = MessageBus()
