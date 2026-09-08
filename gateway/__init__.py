"""Compatibility shim. Prefer ``tap_sdk.gateway`` from the published extra."""
from tap_sdk.gateway import create_app, GatewayConfig, load_config

__all__ = ["create_app", "GatewayConfig", "load_config"]
