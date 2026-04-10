import asyncio
import random
from datetime import datetime, timezone
from typing import Optional, List, Type
from loguru import logger
from core.config import settings
from core.scope import ScopeManager
from core.session import ScanSession
from db.models import Scan, ScanStatus, ScanType


class BaseModule:
    """
    Every scanning module inherits from this.
    Modules implement the `run()` method.
    """
    name: str = "base"
    description: str = ""

    def __init__(self, engine: "ScanEngine"):
        self.engine = engine
        self.session = engine.session
        self.config = engine.config

    async def run(self) -> List[dict]:
        """
        Execute the module. Returns a list of finding dicts.
        Subclasses must override this.
        """
        raise NotImplementedError(f"Module '{self.name}' must implement run()")

    async def log_request(self, method: str, url: str, **kwargs) -> None:
        """Helper to log outgoing requests to the audit log."""
        logger.debug(f"[{self.name}] {method} {url}")
        # In later phases this will write to RequestLog table


class ScanEngine:
    """
    Central orchestrator for a scan run.
    Controls module execution, rate limiting, and result collection.
    """

    def __init__(
        self,
        target_url: str,
        scan_id: str,
        scan_type: ScanType = ScanType.FULL,
        rate_limit: Optional[int] = None,
        timeout: Optional[int] = None,
        modules: Optional[List[Type[BaseModule]]] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.scan_id = scan_id
        self.scan_type = scan_type
        self.rate_limit = rate_limit or settings.scan.default_rate_limit
        self.timeout = timeout or settings.scan.default_timeout
        self.modules = modules or []
        self.findings: List[dict] = []
        self.status = ScanStatus.PENDING
        self.started_at: Optional[datetime] = None
        self.finished_at: Optional[datetime] = None
        self.config = settings

        # Rate limiting: token bucket via asyncio.Semaphore
        self._semaphore = asyncio.Semaphore(self.rate_limit)

        # Scope enforcer
        self.scope = ScopeManager(target_url)

        # HTTP session wrapper
        self.session = ScanSession(
            base_url=target_url,
            timeout=self.timeout,
            user_agent=random.choice(settings.scan.user_agents),
        )

    async def __aenter__(self):
        await self.session.open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    async def run(self) -> dict:
        """
        Run all registered modules sequentially (parallel in later phases).
        Returns a summary dict.
        """
        if not self.scope.is_target_allowed():
            logger.error(f"Target {self.target_url} is out of scope. Aborting.")
            self.status = ScanStatus.FAILED
            return self._summary(error="Target blocked by scope rules.")

        self.status = ScanStatus.RUNNING
        self.started_at = datetime.now(timezone.utc)
        logger.info(f"[Engine] Starting scan {self.scan_id} against {self.target_url}")
        logger.info(f"[Engine] Type: {self.scan_type} | Modules: {len(self.modules)}")

        for ModuleClass in self.modules:
            module = ModuleClass(engine=self)
            logger.info(f"[Engine] Running module: {module.name}")
            try:
                results = await module.run()
                self.findings.extend(results)
                logger.success(f"[Engine] Module '{module.name}' finished — {len(results)} findings")
            except Exception as e:
                logger.error(f"[Engine] Module '{module.name}' crashed: {e}")

        self.status = ScanStatus.COMPLETED
        self.finished_at = datetime.now(timezone.utc)
        duration = (self.finished_at - self.started_at).total_seconds()
        logger.success(f"[Engine] Scan {self.scan_id} complete in {duration:.1f}s — {len(self.findings)} total findings")
        return self._summary()

    async def throttled_request(self, coro):
        """
        Wrap any async request coroutine in the rate-limit semaphore.
        Usage: response = await engine.throttled_request(session.get(url))
        """
        async with self._semaphore:
            result = await coro
            # Enforce spacing between requests
            await asyncio.sleep(1 / self.rate_limit)
            return result

    def _summary(self, error: Optional[str] = None) -> dict:
        return {
            "scan_id": self.scan_id,
            "target": self.target_url,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "error": error,
        }

# Add this to the bottom of core/engine.py

class ReconPipeline:
    """
    Convenience class that bundles all Phase 2 recon modules
    into a single runnable pipeline.
    """

    @staticmethod
    def get_modules():
        """Return all recon module classes in execution order."""
        from modules.recon.dns import DNSModule
        from modules.recon.subdomain import SubdomainModule
        from modules.recon.tech_detect import TechDetectModule
        from modules.recon.whois_lookup import WHOISModule
        from modules.recon.headers import HeaderAnalyzerModule

        return [
            DNSModule,
            WHOISModule,
            SubdomainModule,
            TechDetectModule,
            HeaderAnalyzerModule,
        ]
    
    