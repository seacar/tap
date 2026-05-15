#!/usr/bin/env python3
"""Local entrypoint for the TAP Inspector web UI.

    python inspector/serve.py

Binds 127.0.0.1 only by default (unlike the Verifier's production 0.0.0.0
convention) — this tool mints and signs test keys and shouldn't be reachable
from the network by default.
"""
import os
import sys
from pathlib import Path

#  -> makes the `inspector` package importable for uvicorn's
# string-based "inspector.app:app" load; inspector/app.py's own header adds
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("INSPECTOR_PORT", "8765"))
    reload = os.environ.get("INSPECTOR_RELOAD") == "1"
    uvicorn.run("inspector.app:app", host="127.0.0.1", port=port, reload=reload)
