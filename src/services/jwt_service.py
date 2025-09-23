import jwt
from datetime import datetime, timedelta
from config import Config
from jwt import ExpiredSignatureError, InvalidTokenError

def generate_jwt(seller_id: int) -> str:
    payload = {
        "id": seller_id,
        "exp": datetime.utcnow() + timedelta(hours=Config.JWT_EXP_HOURS)
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm="HS256")

def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=["HS256"])
    except ExpiredSignatureError:
        raise
    except InvalidTokenError:
        raise
