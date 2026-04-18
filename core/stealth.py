"""
Stealth & Rate Limiting Engine
Controls how aggressively the scanner sends requests.
Three modes:
  normal  — standard rate limiting, consistent UA
  polite  — slower, randomized delays, rotated UA
  stealth — maximum evasion: long delays, full UA rotation,
             randomized headers, jitter, human-like patterns
"""
import asyncio
import random
import time
from typing import List, Optional
from loguru import logger


# Real browser user agent strings
USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    # Chrome Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.105 Mobile Safari/537.36",
]

# Accept-Language values to rotate
ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.8,de;q=0.6",
    "en-US,en;q=0.9,es;q=0.8",
]

# Accept headers to rotate
ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
]


class StealthConfig:
    """Configuration for a specific stealth mode."""

    def __init__(
        self,
        mode:               str   = "normal",
        min_delay:          float = 0.0,
        max_delay:          float = 0.2,
        jitter:             float = 0.0,
        rotate_ua:          bool  = False,
        rotate_headers:     bool  = False,
        randomize_order:    bool  = False,
        max_concurrent:     int   = 10,
        request_timeout:    int   = 10,
    ):
        self.mode            = mode
        self.min_delay       = min_delay
        self.max_delay       = max_delay
        self.jitter          = jitter
        self.rotate_ua       = rotate_ua
        self.rotate_headers  = rotate_headers
        self.randomize_order = randomize_order
        self.max_concurrent  = max_concurrent
        self.request_timeout = request_timeout


# Preset configurations for each stealth mode
STEALTH_PRESETS = {
    "normal": StealthConfig(
        mode="normal",
        min_delay=0.0,
        max_delay=0.2,
        jitter=0.0,
        rotate_ua=False,
        rotate_headers=False,
        randomize_order=False,
        max_concurrent=20,
    ),
    "polite": StealthConfig(
        mode="polite",
        min_delay=0.5,
        max_delay=2.0,
        jitter=0.3,
        rotate_ua=True,
        rotate_headers=False,
        randomize_order=False,
        max_concurrent=5,
    ),
    "stealth": StealthConfig(
        mode="stealth",
        min_delay=2.0,
        max_delay=8.0,
        jitter=1.5,
        rotate_ua=True,
        rotate_headers=True,
        randomize_order=True,
        max_concurrent=2,
    ),
}


class StealthEngine:
    """
    Wraps all request timing and header randomization logic.
    Used by the ScanEngine to throttle and disguise requests.
    """

    def __init__(self, mode: str = "normal"):
        self.config   = STEALTH_PRESETS.get(mode, STEALTH_PRESETS["normal"])
        self._sem     = asyncio.Semaphore(self.config.max_concurrent)
        self._ua_pool = USER_AGENTS.copy()
        self._request_count = 0
        self._start_time    = time.monotonic()
        logger.info(
            f"[Stealth] Mode: {mode} | "
            f"Concurrency: {self.config.max_concurrent} | "
            f"Delay: {self.config.min_delay}-{self.config.max_delay}s"
        )

    async def acquire(self) -> None:
        """Wait for the semaphore and apply delay before each request."""
        await self._sem.acquire()
        await self._apply_delay()

    def release(self) -> None:
        """Release the semaphore after a request completes."""
        self._sem.release()

    async def _apply_delay(self) -> None:
        """Calculate and sleep for the appropriate delay."""
        if self.config.max_delay <= 0:
            return

        base_delay = random.uniform(
            self.config.min_delay,
            self.config.max_delay,
        )
        jitter = random.uniform(0, self.config.jitter)
        total  = base_delay + jitter

        if total > 0:
            await asyncio.sleep(total)

        self._request_count += 1

    def get_headers(self, base_ua: Optional[str] = None) -> dict:
        """
        Build an HTTP headers dict with optional rotation.
        In stealth mode, every request looks like a different browser.
        """
        ua = base_ua or USER_AGENTS[0]

        if self.config.rotate_ua:
            ua = random.choice(USER_AGENTS)

        headers = {
            "User-Agent":      ua,
            "Accept":          random.choice(ACCEPT_HEADERS) if self.config.rotate_headers
                               else ACCEPT_HEADERS[0],
            "Accept-Language": random.choice(ACCEPT_LANGUAGES) if self.config.rotate_headers
                               else ACCEPT_LANGUAGES[0],
            "Accept-Encoding": "gzip, deflate, br",
            "Connection":      "keep-alive",
        }

        if self.config.rotate_headers:
            # Randomly include optional headers real browsers send
            if random.random() > 0.5:
                headers["DNT"] = "1"
            if random.random() > 0.7:
                headers["Upgrade-Insecure-Requests"] = "1"
            if random.random() > 0.6:
                headers["Cache-Control"] = random.choice([
                    "no-cache", "max-age=0", "no-store"
                ])

        return headers

    def shuffle_if_needed(self, items: list) -> list:
        """Randomize request order in stealth mode to avoid pattern detection."""
        if self.config.randomize_order:
            shuffled = items.copy()
            random.shuffle(shuffled)
            return shuffled
        return items

    @property
    def stats(self) -> dict:
        elapsed = time.monotonic() - self._start_time
        rps = self._request_count / elapsed if elapsed > 0 else 0
        return {
            "requests_sent": self._request_count,
            "elapsed_s":     round(elapsed, 1),
            "avg_rps":       round(rps, 2),
            "mode":          self.config.mode,
        }
    
    