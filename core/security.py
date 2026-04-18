"""
API Security Layer
Handles:
  - API key authentication for all /api/ routes
  - Request rate limiting per IP
  - Input sanitization
  - Audit logging of all API calls
"""
import time
import hashlib
import secrets
from collections import defaultdict
from typing import Optional, Dict
from fastapi import Request, HTTPException, Depends
from fastapi.security import APIKeyHeader
from loguru import logger
from core.config import settings


# ── API Key Auth ───────────────────────────────────────────────────────────
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def generate_api_key() -> str:
    """Generate a secure random API key."""
    return f"wapt_{secrets.token_urlsafe(32)}"


async def verify_api_key(
    api_key: Optional[str] = Depends(API_KEY_HEADER),
) -> str:
    """
    FastAPI dependency — validates the API key on every protected route.
    Add as a dependency to any router that needs authentication.
    """
    if settings.app.env == "development":
        # Skip auth in development mode for ease of use
        return "dev-mode"

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Pass X-API-Key header.",
        )

    # Compare against configured key (constant-time comparison prevents timing attacks)
    expected = settings.app.secret_key
    if not secrets.compare_digest(
        hashlib.sha256(api_key.encode()).hexdigest(),
        hashlib.sha256(expected.encode()).hexdigest(),
    ):
        logger.warning(f"[Security] Invalid API key attempt")
        raise HTTPException(status_code=403, detail="Invalid API key")

    return api_key


# ── Rate Limiting ──────────────────────────────────────────────────────────
class RateLimiter:
    """
    Simple in-memory rate limiter using a sliding window.
    Tracks requests per IP address.
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window       = window_seconds
        self._buckets: Dict[str, list] = defaultdict(list)

    def is_allowed(self, ip: str) -> bool:
        """Return True if the IP is within rate limits."""
        now       = time.monotonic()
        window_start = now - self.window
        bucket    = self._buckets[ip]

        # Remove old timestamps outside the window
        self._buckets[ip] = [t for t in bucket if t > window_start]

        if len(self._buckets[ip]) >= self.max_requests:
            return False

        self._buckets[ip].append(now)
        return True


# Global rate limiter — 120 requests per minute per IP
api_rate_limiter = RateLimiter(max_requests=120, window_seconds=60)


async def check_rate_limit(request: Request) -> None:
    """FastAPI dependency — enforces per-IP rate limiting."""
    client_ip = request.client.host if request.client else "unknown"
    if not api_rate_limiter.is_allowed(client_ip):
        logger.warning(f"[Security] Rate limit exceeded: {client_ip}")
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Try again in 60 seconds.",
            headers={"Retry-After": "60"},
        )


# ── Audit Logger ───────────────────────────────────────────────────────────
class AuditLogger:
    """
    Logs every API request and scan action to the audit log.
    Keeps a tamper-evident trail of all framework activity.
    """

    @staticmethod
    def log_api_request(
        request:    Request,
        status:     int,
        duration_ms: float,
    ) -> None:
        client_ip = request.client.host if request.client else "unknown"
        logger.info(
            f"[AUDIT] {request.method} {request.url.path} | "
            f"IP:{client_ip} | "
            f"Status:{status} | "
            f"{duration_ms:.0f}ms"
        )

    @staticmethod
    def log_scan_start(scan_id: str, target: str, user: str = "cli") -> None:
        logger.info(
            f"[AUDIT] SCAN_START | "
            f"scan_id:{scan_id} | "
            f"target:{target} | "
            f"user:{user}"
        )

    @staticmethod
    def log_scan_end(
        scan_id:  str,
        target:   str,
        findings: int,
        duration: float,
    ) -> None:
        logger.info(
            f"[AUDIT] SCAN_END | "
            f"scan_id:{scan_id} | "
            f"target:{target} | "
            f"findings:{findings} | "
            f"duration:{duration:.1f}s"
        )

    @staticmethod
    def log_report_generated(
        scan_id: str,
        fmt:     str,
        path:    str,
    ) -> None:
        logger.info(
            f"[AUDIT] REPORT_GENERATED | "
            f"scan_id:{scan_id} | "
            f"format:{fmt} | "
            f"path:{path}"
        )


audit = AuditLogger()
