# api/health.py
import os as _os, sys as _sys
_lib = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', 'lib')
if _lib not in _sys.path:
    _sys.path.insert(0, _lib)

"""GET /api/health — simple liveness probe."""
import json
import os
import sys


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
