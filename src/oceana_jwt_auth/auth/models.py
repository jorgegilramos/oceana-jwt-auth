from flask_restx import fields, Model

bearer_token_model = Model("Token", {
    "token": fields.String(
        description="Bearer token",
        pattern="Bearer [a-zA-Z_\\d]{100}"),
    "expiresIn": fields.String(
        description="Token expiration date"
    )
})
