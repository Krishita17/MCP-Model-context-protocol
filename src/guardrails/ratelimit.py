"""Token-bucket rate limiter."""

from __future__ import annotations

import time


class RateLimitExceeded(Exception):
    """Raised when the rate limit is exceeded."""


class RateLimiter:
    """Token-bucket rate limiter.

    Parameters
    ----------
    rate:
        Tokens added per second.
    capacity:
        Maximum burst size.
    """

    def __init__(self, rate: float, capacity: float) -> None:
        self.rate = rate
        self.capacity = capacity
        self._tokens = capacity
        self._last = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last = now

    def acquire(self, tokens: float = 1) -> None:
        """Consume *tokens*, raising ``RateLimitExceeded`` if insufficient."""
        self._refill()
        if tokens > self._tokens:
            raise RateLimitExceeded(
                f"Need {tokens} tokens, only {self._tokens:.2f} available"
            )
        self._tokens -= tokens

    def try_acquire(self, tokens: float = 1) -> bool:
        """Return ``True`` and consume if enough tokens, else ``False``."""
        try:
            self.acquire(tokens)
            return True
        except RateLimitExceeded:
            return False
