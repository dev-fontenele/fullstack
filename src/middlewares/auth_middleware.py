from functools import wraps
from flask import request, jsonify, g
from src.services.jwt_service import decode_jwt
from jwt import ExpiredSignatureError, InvalidTokenError

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", None)
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"message": "Authorization header missing or malformed"}), 401

        token = auth_header.split(" ")[1]
        try:
            payload = decode_jwt(token)
            g.seller_id = payload.get("id")
        except ExpiredSignatureError:
            return jsonify({"message": "Token expirado"}), 401
        except InvalidTokenError:
            return jsonify({"message": "Token inválido"}), 401

        return f(*args, **kwargs)
    return decorated
