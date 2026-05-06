import json
def handler(request, context=None):
    if request.method == "OPTIONS":
        return {"statusCode":204,"headers":{"Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET,OPTIONS","Access-Control-Allow-Headers":"Content-Type,Authorization"},"body":""}
    return {"statusCode":200,"headers":{"Content-Type":"application/json","Access-Control-Allow-Origin":"*"},"body":json.dumps({"status":"ok","service":"Phantasm-DB"})}
