"""Compatibility shim. The Gateway is packaged as ``tap_sdk.gateway``."""
from tap_sdk.gateway.keys import JWKSCache

__all__ = ["JWKSCache"]
