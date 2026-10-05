"""
BugFlow Elite v6 — Config Loader
Loads config.yaml and overlays environment variable overrides.
Tinlance Limited | LloydCoder
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_CONFIG_CACHE = None


def load_config(config_path: str = "./config/config.yaml") -> dict:
    """
    Load the master config.yaml file.
    Environment variables override config values using double-underscore
    notation: BUGFLOW__AI__FALLBACK__API_KEY overrides ai.fallback.api_key
    """
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path, "r") as f:
        config = yaml.safe_load(f)

    # Apply env var overrides
    _apply_env_overrides(config)

    # Apply secrets from dedicated env vars (cleaner pattern)
    _apply_api_keys(config)

    _CONFIG_CACHE = config
    logger.info(f"Config loaded from {config_path}")
    return config


def _apply_env_overrides(config: dict, prefix: str = "BUGFLOW"):
    """Recursively apply BUGFLOW__SECTION__KEY env vars to config dict."""
    for key, value in os.environ.items():
        if not key.startswith(prefix + "__"):
            continue
        parts = key[len(prefix) + 2:].lower().split("__")
        _set_nested(config, parts, value)


def _set_nested(d: dict, keys: list, value: Any):
    """Set a nested dict value by key path."""
    for key in keys[:-1]:
        d = d.setdefault(key, {})
    # Auto-cast booleans and numbers
    if value.lower() in ("true", "yes", "1"):
        value = True
    elif value.lower() in ("false", "no", "0"):
        value = False
    else:
        try:
            value = int(value)
        except ValueError:
            try:
                value = float(value)
            except ValueError:
                pass
    d[keys[-1]] = value


def _apply_api_keys(config: dict):
    """Apply well-known API key env vars directly."""
    mappings = {
        "XAI_API_KEY":          ["ai", "fallback", "api_key"],
        "ANTHROPIC_API_KEY":    ["ai", "secondary_fallback", "api_key"],
        "GITHUB_TOKEN":         ["recon", "bbot", "api_keys", "github"],
        "SHODAN_API_KEY":       ["recon", "bbot", "api_keys", "shodan"],
        "SECURITYTRAILS_KEY":   ["recon", "bbot", "api_keys", "securitytrails"],
        "VIRUSTOTAL_KEY":       ["recon", "bbot", "api_keys", "virustotal"],
        "CHAOS_KEY":            ["recon", "bbot", "api_keys", "chaos"],
        "URLSCAN_KEY":          ["recon", "bbot", "api_keys", "urlscan"],
        "H1_API_TOKEN":         ["hackerone", "api_token"],
        "H1_USERNAME":          ["hackerone", "username"],
        "TELEGRAM_BOT_TOKEN":   ["telegram", "bot_token"],
        "TELEGRAM_CHAT_ID":     ["telegram", "chat_id"],
        "THREATFADE_API_KEY":   ["threatfade", "api_key"],
        "THREATFADE_URL":       ["threatfade", "base_url"],
        "BUGCROWD_API_TOKEN":   ["bugcrowd", "api_token"],
        "INTIGRITI_TOKEN":      ["intigriti", "api_token"],
        "YESWEHACK_TOKEN":      ["yeswehack", "api_token"],
        "GITHOUND_TOKEN":       ["scanner", "githound", "github_token"],
        "NETLAS_API_KEY":       ["recon", "netlas", "api_key"],
    }
    for env_var, path in mappings.items():
        val = os.environ.get(env_var)
        if val:
            _set_nested(config, path, val)


def get(config: dict, *keys, default=None) -> Any:
    """Safe nested get: get(cfg, 'ai', 'primary', 'model', default='llama3')"""
    d = config
    for key in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(key)
        if d is None:
            return default
    return d


def validate_config(config: dict) -> list[str]:
    """
    Validate the config and return a list of warnings.
    Does NOT raise exceptions — BugFlow runs with warnings.
    """
    warnings = []

    if not get(config, "hackerone", "api_token"):
        warnings.append("H1_API_TOKEN not set — HackerOne draft creation disabled")

    if not get(config, "telegram", "bot_token"):
        warnings.append("TELEGRAM_BOT_TOKEN not set — Telegram alerts disabled")

    if not get(config, "ai", "fallback", "api_key"):
        primary = get(config, "ai", "primary", "provider")
        if primary != "ollama":
            warnings.append("No AI API key set — falling back to Ollama only")

    if get(config, "hackerone", "auto_submit"):
        warnings.append("CRITICAL: auto_submit is TRUE — this should always be false")

    active_programs = []
    manual_scope = Path("./config/scope/manual_scope.yaml")
    if manual_scope.exists():
        with open(manual_scope) as f:
            scope_data = yaml.safe_load(f)
            programs = scope_data.get("programs", [])
            active_programs = [p for p in programs if p.get("active")]

    if not active_programs and not get(config, "scope", "auto_fetch"):
        warnings.append("No active programs in scope — BugFlow has no targets to scan")

    return warnings
