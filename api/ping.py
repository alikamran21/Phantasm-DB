import json
def handler(request, context=None):
    return {"statusCode":200,"headers":{"Content-Type":"application/json","Access-Control-Allow-Origin":"*"},"body":json.dumps({"pong":True})}
