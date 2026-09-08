"""Compatibility shim. The Gateway is packaged as ``tap_sdk.gateway``."""
from tap_sdk.gateway.app import create_app

__all__ = ["create_app"]
