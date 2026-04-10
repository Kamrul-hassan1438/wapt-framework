import httpx
from typing import Optional, Dict, Any
from loguru import logger
from core.config import settings


class ScanSession:
    """
    Async HTTP session wrapper for all scan requests.
    Handles headers, cookies, redirects, and timeouts consistently.
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        user_agent: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = False,  # off by default for pentest targets
    ):
        self.base_url = base_url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._client: Optional[httpx.AsyncClient] = None

        self._headers = {
            "User-Agent": user_agent or settings.scan.user_agents[0],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if extra_headers:
            self._headers.update(extra_headers)

        self._cookies = cookies or {}

    async def open(self) -> None:
        """Open the underlying HTTP client."""
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._headers,
            cookies=self._cookies,
            timeout=self.timeout,
            follow_redirects=True,
            max_redirects=settings.scan.max_redirects,
            verify=self.verify_ssl,
        )
        logger.debug(f"[Session] Opened HTTP client for {self.base_url}")

    async def close(self) -> None:
        """Close the HTTP client and release connections."""
        if self._client:
            await self._client.aclose()
            logger.debug("[Session] HTTP client closed")

    def _ensure_open(self) -> None:
        if self._client is None:
            raise RuntimeError("ScanSession not opened. Use 'async with engine:' or call open() first.")

    async def get(self, url: str, **kwargs) -> httpx.Response:
        self._ensure_open()
        logger.debug(f"[Session] GET {url}")
        return await self._client.get(url, **kwargs)

    async def post(self, url: str, data: Any = None, json: Any = None, **kwargs) -> httpx.Response:
        self._ensure_open()
        logger.debug(f"[Session] POST {url}")
        return await self._client.post(url, data=data, json=json, **kwargs)

    async def put(self, url: str, **kwargs) -> httpx.Response:
        self._ensure_open()
        return await self._client.put(url, **kwargs)

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        self._ensure_open()
        return await self._client.delete(url, **kwargs)

    def set_cookie(self, name: str, value: str) -> None:
        if self._client:
            self._client.cookies.set(name, value)

    def set_header(self, name: str, value: str) -> None:
        if self._client:
            self._client.headers[name] = value