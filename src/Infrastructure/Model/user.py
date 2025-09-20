from src.config.data_base import db 
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
<<<<<<< HEAD
=======
    cnpj = db.Column(db.String(100), nullable=False)
    celular = db.Coumn(db.String(100), nullable=False)
    status = db.Column(db.String(100), nullable=False)
>>>>>>> 5a35374bccbf8b50db198fab534d1f1dc3da41ef

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "password": self.password
        }
