from flask import request, jsonify, make_response
from src.Application.Service.user_service import UserService
from src.Infrastructure.http.whats_app import generate_code, send_whatsapp


class UserController:
    @staticmethod
    def register_user():
        data = request.get_json()

        name = data.get('name')
        cnpj = data.get('cnpj')
        email = data.get('email')
        phone = data.get('phone')
        password = data.get('password')

        if not name or not cnpj or not email or not phone or not password:
            return make_response(jsonify({"error": "Missing required fields"}), 400)

        user = UserService.create_user(name, cnpj, email, phone, password)

        activation_code = generate_code()

        send_whatsapp(phone, activation_code)

        return make_response(jsonify({
            "message": "User created successfully. Activation code sent via WhatsApp.",
            "user": user.to_dict(),
            "status": "inactive"
        }), 200)

