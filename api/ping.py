def handler(request, context=None):
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"}, "body": '{"ping":"pong"}'}
