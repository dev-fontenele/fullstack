# src/config/data_base.py
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os

# Carrega variáveis do .env
load_dotenv()  

db = SQLAlchemy()

def init_db(app):
    # Obtém a URL do banco de dados
    db_uri = os.getenv("DATABASE_URL")
    if not db_uri:
        raise ValueError(
            "A variável DATABASE_URL não foi encontrada no .env. "
            "Verifique se ela está definida corretamente."
        )

    print("Conectando ao banco de dados com:", db_uri)  # DEBUG

    # Configura o Flask com SQLAlchemy
    app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    # Cria todas as tabelas definidas nos models
    with app.app_context():
        db.create_all()
        print("Tabelas criadas com sucesso!")
