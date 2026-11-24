"""Per-session risk scoring and windowed scan (PDR 6.3.6)."""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field


@dataclass
class SessionState:
    session_id: str
    score: float = 0.0
    turns: list[str] = field(default_factory=list)
    updated: float = field(default_factory=time.monotonic)
    locked: bool = False

    def decay(self, rate: float) -> None:
        if rate <= 0:
            return
        minutes = max(0.0, (time.monotonic() - self.updated) / 60.0)
        self.score = max(0.0, self.score - minutes * rate)


class SessionStore:
    """In-memory store with a size cap and idle eviction.

    Redis is the optional multi-instance upgrade (PDR 4.2).
    """

    def __init__(self, max_sessions: int = 10000, safe: int = 6, lock_at: int = 12, decay: float = 1.0, window: int = 4) -> None:
        self.max_sessions = max_sessions
        self.safe = safe
        self.lock_at = lock_at
        self.decay = decay
        self.window = window
        self._items: OrderedDict[str, SessionState] = OrderedDict()
        self._lock = threading.RLock()

    def get(self, session_id: str) -> SessionState:
        with self._lock:
            state = self._items.get(session_id)
            if state is None:
                state = SessionState(session_id=session_id)
                self._items[session_id] = state
                if len(self._items) > self.max_sessions:
                    self._items.popitem(last=False)
            return state

    def add_turn(self, session_id: str, text: str, points: float = 0.0) -> SessionState:
        with self._lock:
            state = self.get(session_id)
            state.decay(self.decay)
            state.score += points
            state.turns.append(text)
            state.turns = state.turns[-self.window :]
            state.updated = time.monotonic()
            if state.score >= self.lock_at:
                state.locked = True
            return state

    def window_text(self, session_id: str) -> str:
        with self._lock:
            state = self._items.get(session_id)
            if not state:
                return ""
            return "\n".join(state.turns[-self.window :])

    def level(self, session_id: str) -> str:
        """Return normal, safe or locked."""
        with self._lock:
            state = self._items.get(session_id)
            if state is None:
                return "normal"
            state.decay(self.decay)
            state.updated = time.monotonic()
            if state.locked or state.score >= self.lock_at:
                return "locked"
            if state.score >= self.safe:
                return "safe"
            return "normal"

    def reset(self) -> None:
        with self._lock:
            self._items.clear()
