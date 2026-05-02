# api/_handler_base.py
"""
Minimal Vercel Python serverless helper.

Vercel Python runtime calls handler(request, context) where request has:
  .method       str
  .headers      dict-like
  .body         bytes
  .query        dict   (parsed query string)

We wrap that into simple helpers so each route file is clean.
"""
import json
import os
from typing import Any


def cors_headers(methods: str = "POST, OPTIONS") -> dict:
    origin = os.environ.get("ALLOWED_ORIGINS", "*").split(",")[0].strip()
    return {
        "Access-Control-Allow-Origin":  origin,
        "Access-Control-Allow-Methods": f"{methods}",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Content-Type": "application/json",
    }


def ok(data: Any, status: int = 200) -> dict:
    return {"statusCode": status, "headers": cors_headers(), "body": json.dumps(data)}


def err(detail: str, status: int = 400) -> dict:
    return {"statusCode": status, "headers": cors_headers(), "body": json.dumps({"detail": detail})}


def preflight() -> dict:
    return {"statusCode": 204, "headers": cors_headers(), "body": ""}


def parse_body(request) -> dict:
    try:
        raw = getattr(request, "body", b"") or b""
        if isinstance(raw, str):
            raw = raw.encode()
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def get_bearer_token(request) -> str | None:
    auth = ""
    if hasattr(request, "headers"):
        hdrs = request.headers
        auth = hdrs.get("Authorization", hdrs.get("authorization", ""))
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


def client_ip(request) -> str:
    hdrs = request.headers if hasattr(request, "headers") else {}
    xff  = hdrs.get("x-forwarded-for", hdrs.get("X-Forwarded-For", ""))
    return xff.split(",")[0].strip() if xff else "unknown"
