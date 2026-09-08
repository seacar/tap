#!/usr/bin/env python3
"""Compatibility entrypoint. Prefer ``python -m tap_sdk.gateway.serve``."""
from tap_sdk.gateway.serve import main

if __name__ == "__main__":
    main()
