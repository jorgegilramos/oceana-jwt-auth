from .models import bearer_token_model


token_doc = {
    "params": {
        "body": {
            "description": "JSON data for the api",
            "in": "body",
            "type": "schema",
            "required": True,
            "schema": {
                "required": ["client_id", "client_secret"],
                "type": "object",
                "properties": {
                    "client_id": {"type": "string", "description": "Client identifier"},
                    "client_secret": {"type": "string", "description": "Client secret"}
                }
            }
        }
    },
    "description": "Authentication",
    "responses": {
        200: ("Created OK", bearer_token_model),
        # 200: ("Created OK"),
        400: "Error",
        401: "Unauthorized",
        403: "Forbidden",
        500: "Internal Server Error"
    }
}
