from src.config.data_base import db
from src.Infrastructure.Model.user import User
from passlib.context import CryptContext
pwd_ctx = CryptContext(
    schemes=["pbkdf2_sha256"],
    pbkdf2_sha256__default_rounds=30000,
)

class UserService:
    @staticmethod
    def create_user(name, email, password, cnpj=None, celular=None, status="ativo"):
        user = User(
            name=name,
            email=email,
            password=password,
            cnpj=cnpj or "00000000000000",
            celular=celular or "00000000000",
            status=status
        )
        user.password = pwd_ctx.hash(password)
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def authenticate_user(email, password):
        user = User.query.filter_by(email=email).first()
        if not user:
            return None

        stored = getattr(user, "password", None)
        if not stored:
            return None

        try:
            valid = pwd_ctx.verify(password, stored)
        except Exception:
            return None

        if not valid:
            return None

        return user