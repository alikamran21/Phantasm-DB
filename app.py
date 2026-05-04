"""
app.py — Flask wrapper for Phantasm-DB
Adapts each Vercel-style handler(request, context) into a Flask route.

Each /api/*.py file exposes a `handler(request, context=None)` function that
expects a request object with:
  - request.method  (str)
  - request.headers (dict-like)
  - request.body    (bytes)

And returns a dict: {"statusCode": int, "headers": dict, "body": str}

This wrapper bridges Flask's `request` object to that interface.
"""

import os
from flask import Flask, request, Response
from dotenv import load_dotenv

# Load .env file (DATABASE_URL and other secrets)
load_dotenv()

# ── Import all API handlers ───────────────────────────────────────────────────
from api.health        import handler as health_handler
from api.initdb        import handler as initdb_handler
from api.login         import handler as login_handler
from api.lookup        import handler as lookup_handler
from api.verifyotp     import handler as verifyotp_handler
from api.patients      import handler as patients_handler
from api.notes         import handler as notes_handler
from api.doctorprofile import handler as doctorprofile_handler
from api.patientprofile import handler as patientprofile_handler
from api.appointment   import handler as appointment_handler
from api.auditlogs     import handler as auditlogs_handler
from api.flaggedusers  import handler as flaggedusers_handler
from api.unflaguser    import handler as unflaguser_handler
from api.ping          import handler as ping_handler

app = Flask(__name__)

# ── Request adapter ───────────────────────────────────────────────────────────

class VercelRequest:
    """
    Wraps a Flask request so existing Vercel-style handlers need zero changes.
    Provides: .method, .headers (plain dict), .body (bytes)
    """
    def __init__(self, flask_request):
        self.method  = flask_request.method
        self.headers = dict(flask_request.headers)
        self.body    = flask_request.get_data()          # raw bytes
        self.args    = flask_request.args                # query params (bonus)


def flask_response(result: dict) -> Response:
    """Convert a Vercel-style handler result dict into a Flask Response."""
    status  = result.get("statusCode", 200)
    headers = result.get("headers", {})
    body    = result.get("body", "")
    resp = Response(body, status=status)
    for k, v in headers.items():
        resp.headers[k] = v
    return resp


def make_route(handler_fn):
    """Return a Flask view function that calls a Vercel-style handler."""
    def view():
        vreq = VercelRequest(request)
        result = handler_fn(vreq)
        return flask_response(result)
    view.__name__ = handler_fn.__name__   # Flask requires unique endpoint names
    return view


# ── Register routes (mirrors vercel.json) ────────────────────────────────────

ROUTES = [
    ("/api/health",         health_handler,         ["GET",  "OPTIONS"]),
    ("/api/initdb",         initdb_handler,         ["POST", "OPTIONS"]),
    ("/api/login",          login_handler,          ["POST", "OPTIONS"]),
    ("/api/lookup",         lookup_handler,         ["POST", "OPTIONS"]),
    ("/api/verifyotp",      verifyotp_handler,      ["POST", "OPTIONS"]),
    ("/api/patients",       patients_handler,       ["GET",  "OPTIONS"]),
    ("/api/notes",          notes_handler,          ["GET",  "POST", "OPTIONS"]),
    ("/api/doctorprofile",  doctorprofile_handler,  ["GET",  "OPTIONS"]),
    ("/api/patientprofile", patientprofile_handler, ["GET",  "POST", "OPTIONS"]),
    ("/api/appointment",    appointment_handler,    ["GET",  "POST", "OPTIONS"]),
    ("/api/auditlogs",      auditlogs_handler,      ["GET",  "OPTIONS"]),
    ("/api/flaggedusers",   flaggedusers_handler,   ["GET",  "OPTIONS"]),
    ("/api/unflaguser",     unflaguser_handler,     ["POST", "OPTIONS"]),
    ("/api/ping",           ping_handler,           ["GET",  "OPTIONS"]),
]

for path, handler_fn, methods in ROUTES:
    app.add_url_rule(path, view_func=make_route(handler_fn), methods=methods)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
