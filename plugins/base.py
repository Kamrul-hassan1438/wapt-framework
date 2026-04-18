"""
Plugin Base Class
Every community or custom plugin inherits from WAPTPlugin.
Plugins are discovered automatically from the plugins/ directory.

To create a plugin:
  1. Create a file in plugins/  e.g. plugins/my_scanner.py
  2. Define a class that inherits WAPTPlugin
  3. Implement the run() method
  4. Add plugin metadata (name, description, version, author)

The plugin will be auto-discovered on the next scan run.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from core.engine import BaseModule


class WAPTPlugin(BaseModule, ABC):
    """
    Base class for all WAPT plugins.
    Inherits from BaseModule — so plugins have full
    access to engine, session, scope, and config.
    """
    # Required metadata — every plugin must define these
    name:        str = "unnamed_plugin"
    version:     str = "0.1.0"
    author:      str = "unknown"
    description: str = ""
    category:    str = "custom"      # recon | scanner | vuln | custom

    # Optional — list of vuln types this plugin tests for
    tests_for: List[str] = []

    @abstractmethod
    async def run(self) -> List[dict]:
        """
        Execute the plugin scan logic.
        Must return a list of finding dicts matching the
        standard finding schema (see db/models.py Finding).
        """
        raise NotImplementedError

    def make_finding(
        self,
        title:        str,
        severity:     str,
        vuln_type:    str,
        url:          str,
        description:  str,
        evidence:     str,
        remediation:  str,
        cvss_score:   float        = 0.0,
        parameter:    Optional[str] = None,
        payload_used: Optional[str] = None,
        references:   List[str]    = None,
        confirmed:    bool         = True,
    ) -> dict:
        """
        Helper to build a correctly structured finding dict.
        Use this instead of building the dict manually.
        """
        return {
            "title":            title,
            "severity":         severity,
            "vuln_type":        vuln_type,
            "url":              url,
            "parameter":        parameter,
            "payload_used":     payload_used,
            "description":      description,
            "evidence":         evidence,
            "remediation":      remediation,
            "cvss_score":       cvss_score,
            "references":       references or [],
            "confirmed":        confirmed,
            "is_false_positive": False,
        }
    
    