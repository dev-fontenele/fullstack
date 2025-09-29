import os
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt

from src.config.data_base import db, init_db
from src.Infrastructure.Model.auth import auth_bp

# Importa o modelo User do caminho correto
from src.Infrastructure.Model.user import User

bcrypt = Bcrypt()

def create_app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")

    jwt = JWTManager(app)
    bcrypt.init_app(app)

    init_db(app)

    app.register_blueprint(auth_bp, url_prefix='/api/auth')

    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5004)