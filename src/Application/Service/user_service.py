from src.config.data_base import db
from src.Infrastructure.Model.user import User

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
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def authenticate_user(email, password):
        return User.query.filter_by(email=email, password=password).first()
