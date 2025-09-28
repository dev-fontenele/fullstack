#Código de conexão com o banco de dados MySQL usando SQLAlchemy e Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def init_db(app):
    app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+mysqldb://user:123user123@localhost/minha_base"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

    with app.app_context():
        db.create_all()
