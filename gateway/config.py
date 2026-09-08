"""Compatibility shim. The Gateway is packaged as ``tap_sdk.gateway``."""
from tap_sdk.gateway.config import GatewayConfig, load_config

__all__ = ["GatewayConfig", "load_config"]
