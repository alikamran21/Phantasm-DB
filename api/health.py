from _shared import *

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    return ok({"status": "ok", "service": "phantasm-db"})
