"""
VoIP OSINT APEX — Pipeline Orchestrator
Manages concurrent execution of plugins and aggregates results.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

from core.plugin_registry import registry
from core.base_plugin import BasePlugin
from utils.exceptions import VoIPOSINTError

log = logging.getLogger("pipeline")

class Pipeline:
    """
    Orchestrates the investigation process by running multiple plugins
    concurrently and handling dependencies/ordering.
    """

    def __init__(self, target: str, target_type: str):
        self.target = target
        self.target_type = target_type  # "number", "ip", "domain", "pcap"
        self.results: Dict[str, Any] = {
            "target": target,
            "type": target_type,
            "start_time": datetime.utcnow().isoformat() + "Z",
            "plugin_results": {}
        }

    async def execute(self, plugin_names: Optional[List[str]] = None):
        """
        Execute the pipeline with selected or all compatible plugins.
        """
        # Discover plugins if registry is empty
        if not registry.plugins:
            registry.discover()

        # Filter plugins by target type compatibility and user selection
        to_run = []
        all_plugins = registry.list_plugins()
        
        for plugin in all_plugins:
            # Basic category/target mapping (can be refined in PluginMetadata)
            if plugin_names and plugin.metadata.name not in plugin_names:
                continue
            
            # TODO: Add more sophisticated target compatibility checking
            to_run.append(plugin)

        if not to_run:
            log.warning(f"No compatible plugins found for target type: {self.target_type}")
            return self.results

        log.info(f"Starting pipeline for {self.target} with {len(to_run)} plugins...")

        # Run plugins concurrently
        tasks = [self._run_plugin(p) for p in to_run]
        await asyncio.gather(*tasks)

        self.results["end_time"] = datetime.utcnow().isoformat() + "Z"
        log.info(f"Pipeline complete for {self.target}")
        return self.results

    async def _run_plugin(self, plugin: BasePlugin):
        """Run a single plugin and capture its output/errors."""
        name = plugin.metadata.name
        log.debug(f"Executing plugin: {name}")
        
        try:
            # Pass common context (API keys, etc.) if needed
            result = await plugin.run(self.target)
            self.results["plugin_results"][name] = {
                "success": True,
                "data": result,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        except VoIPOSINTError as e:
            log.error(f"Plugin '{name}' failed with known error: {e}")
            self.results["plugin_results"][name] = {
                "success": False,
                "error": str(e),
                "type": type(e).__name__
            }
        except Exception as e:
            log.exception(f"Plugin '{name}' crashed with unexpected error: {e}")
            self.results["plugin_results"][name] = {
                "success": False,
                "error": "Unexpected internal error",
                "type": type(e).__name__
            }
