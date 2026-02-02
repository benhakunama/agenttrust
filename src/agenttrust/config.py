"""Configuration management for AgentTrust."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


DEFAULT_CONFIG: Dict[str, Any] = {
    "version": "0.1.0",
    "api_key": "",
    "framework": "langchain",
    "log_level": "INFO",
    "policies": {
        "max_actions_per_minute": 100,
        "require_human_approval": False,
        "auto_block_threshold": 0.2,
        "auto_isolate_threshold": 0.4,
    },
    "compliance": {
        "frameworks": ["EU_AI_ACT", "NIST_RMF", "ISO_42001", "SOC2"],
        "audit_retention_days": 90,
    },
    "alert_webhooks": [],
    "monitoring": {
        "enabled": True,
        "dashboard_refresh_ms": 1000,
        "demo_mode": True,
    },
}

CONFIG_DIR = Path.home() / ".agenttrust"
CONFIG_FILE = CONFIG_DIR / "config.yaml"


class Config:
    """Configuration manager for AgentTrust.

    Supports YAML-based config at ~/.agenttrust/config.yaml with
    environment variable overrides.
    """

    def __init__(self, config_path: Optional[Path] = None) -> None:
        """Initialize configuration.

        Args:
            config_path: Custom config file path (default: ~/.agenttrust/config.yaml).
        """
        self._path = config_path or CONFIG_FILE
        self._data: Dict[str, Any] = dict(DEFAULT_CONFIG)
        self._load()

    def _load(self) -> None:
        """Load configuration from file and environment."""
        # Load from file if exists
        if self._path.exists():
            try:
                with open(self._path, "r") as f:
                    file_data = yaml.safe_load(f) or {}
                self._deep_merge(self._data, file_data)
            except (yaml.YAMLError, OSError):
                pass

        # Override with environment variables
        env_api_key = os.environ.get("AGENTTRUST_API_KEY")
        if env_api_key:
            self._data["api_key"] = env_api_key

        env_framework = os.environ.get("AGENTTRUST_FRAMEWORK")
        if env_framework:
            self._data["framework"] = env_framework

        env_log_level = os.environ.get("AGENTTRUST_LOG_LEVEL")
        if env_log_level:
            self._data["log_level"] = env_log_level

    def save(self) -> Path:
        """Save current configuration to file.

        Returns:
            Path to the saved config file.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as f:
            yaml.dump(self._data, f, default_flow_style=False, sort_keys=False)
        return self._path

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key (supports dot notation).

        Args:
            key: Configuration key (e.g., 'policies.max_actions_per_minute').
            default: Default value if key not found.

        Returns:
            The configuration value.
        """
        keys = key.split(".")
        value: Any = self._data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value (supports dot notation).

        Args:
            key: Configuration key.
            value: Value to set.
        """
        keys = key.split(".")
        data = self._data
        for k in keys[:-1]:
            if k not in data or not isinstance(data[k], dict):
                data[k] = {}
            data = data[k]
        data[keys[-1]] = value

    @property
    def api_key(self) -> str:
        """Get the API key."""
        return self._data.get("api_key", "")

    @property
    def framework(self) -> str:
        """Get the configured framework."""
        return self._data.get("framework", "langchain")

    @property
    def log_level(self) -> str:
        """Get the log level."""
        return self._data.get("log_level", "INFO")

    @property
    def policies(self) -> Dict[str, Any]:
        """Get policy settings."""
        return self._data.get("policies", {})

    @property
    def webhooks(self) -> List[str]:
        """Get alert webhook URLs."""
        return self._data.get("alert_webhooks", [])

    def to_dict(self) -> Dict[str, Any]:
        """Get the full configuration as a dictionary."""
        return dict(self._data)

    @staticmethod
    def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> None:
        """Deep merge override into base dict (modifies base in-place)."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                Config._deep_merge(base[key], value)
            else:
                base[key] = value
