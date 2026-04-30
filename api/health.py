# api/health.py
"""GET /api/health — simple liveness probe."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from _handler_base import cors_headers, preflight


def handler(request, context=None):
    if request.method == "OPTIONS":
        return preflight()

    data = {"status": "ok", "service": "phantasm-db", "env": os.environ.get("APP_ENV", "production")}
    return {
        "statusCode": 200,
        "headers": cors_headers("GET, OPTIONS"),
        "body": json.dumps(data),
    }
