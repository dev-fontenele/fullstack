from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def init_db(app):
    """
    Inicializa a base de dados com o app Flask e o SQLAlchemy.
    """
<<<<<<< HEAD
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root@mysql57:3306/market_management'
=======
    app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+mysqldb://user:123user123@localhost/minha_base"
>>>>>>> b3e452e (atualizações do projeto)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

