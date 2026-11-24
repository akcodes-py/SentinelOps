"""Per-key and per-IP token bucket with idle eviction (PDR 6.3, 6.3.8)."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class Bucket:
    tokens: float
    updated: float
    last_seen: float


class TokenBucketLimiter:
    def __init__(self, capacity: int = 30, refill_per_second: float = 0.5, idle_eviction_seconds: int = 300, max_keys: int = 10000) -> None:
        self.capacity = capacity
        self.refill = refill_per_second
        self.idle = idle_eviction_seconds
        self.max_keys = max_keys
        self._buckets: dict[str, Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self.max_keys:
                    self._evict(now)
                bucket = Bucket(self.capacity, now, now)
                self._buckets[key] = bucket
            bucket.tokens = min(self.capacity, bucket.tokens + (now - bucket.updated) * self.refill)
            bucket.updated = now
            bucket.last_seen = now
            if bucket.tokens < 1:
                return False
            bucket.tokens -= 1
            return True

    def _evict(self, now: float) -> None:
        stale = [k for k, b in self._buckets.items() if now - b.last_seen > self.idle]
        for k in stale:
            self._buckets.pop(k, None)
        while len(self._buckets) >= self.max_keys:
            oldest = min(self._buckets, key=lambda k: self._buckets[k].last_seen)
            self._buckets.pop(oldest, None)
