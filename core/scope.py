from urllib.parse import urlparse
from loguru import logger
from core.config import settings


class ScopeManager:
    """
    Enforces scan boundaries — prevents testing out-of-scope targets.
    This is a critical legal safeguard. Never bypass it.
    """

    def __init__(self, target_url: str, extra_allowed: list[str] | None = None):
        self.target_url = target_url
        self.parsed = urlparse(target_url)
        self.target_host = self.parsed.netloc.lower().split(":")[0]
        self.extra_allowed = [h.lower() for h in (extra_allowed or [])]

    def is_target_allowed(self) -> bool:
        """Check if the primary target is not in the always-blocked list."""
        blocked = settings.scope.always_blocked
        for blocked_domain in blocked:
            if self.target_host == blocked_domain or self.target_host.endswith(f".{blocked_domain}"):
                logger.warning(f"[Scope] Target '{self.target_host}' is in the always-blocked list.")
                return False

        scheme = self.parsed.scheme.lower()
        if scheme not in settings.scope.allowed_schemes:
            logger.warning(f"[Scope] Scheme '{scheme}' is not allowed.")
            return False

        return True

    def is_url_in_scope(self, url: str) -> bool:
        """
        Check if a URL discovered during scanning is within scope.
        Only allows URLs that share the same host as the target.
        """
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower().split(":")[0]

            # Must be same host or explicitly allowed
            in_scope = (
                host == self.target_host
                or host in self.extra_allowed
                or host.endswith(f".{self.target_host}")
            )

            if not in_scope:
                logger.debug(f"[Scope] URL out of scope: {url}")

            return in_scope
        except Exception:
            return False

    def filter_urls(self, urls: list[str]) -> list[str]:
        """Filter a list of URLs to only those in scope."""
        return [url for url in urls if self.is_url_in_scope(url)]