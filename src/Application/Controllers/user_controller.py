from flask import request, jsonify, make_response, redirect, url_for
from src.Application.Service.user_service import UserService


class UserController:
    @staticmethod
    def register_user():
        
        data = request.get_json() if request.is_json else request.form

        user = UserService.create_user(
            name=data.get("name"),
            email=data.get("email"),
            password=data.get("password"),
            cnpj=data.get("cnpj", None),
            celular=data.get("celular", None),
            status=data.get("status", None)
        )

        
        if not request.is_json:
            return redirect(url_for('login_page'))

        
        return jsonify({"mensagem": "User salvo com sucesso", "usuario": user.to_dict()})

    @staticmethod
    def login_user():
        
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        user = UserService.authenticate_user(data.get("email"), data.get("password"))

        if not user:
            if request.is_json:
                return make_response(jsonify({"erro": "Email ou senha inválidos"}), 401)
            else:
                return redirect(url_for('login_page'))  
        
        if request.is_json:
            return make_response(jsonify({"mensagem": "Login bem-sucedido", "usuario": user.to_dict()}), 200)
        else:
            
            return redirect(url_for('index_page'))
