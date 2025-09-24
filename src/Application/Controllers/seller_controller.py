from flask import request, jsonify
from src.Application.Service.seller_service import SellerService

class SellerController:
    @staticmethod
    def register_seller():
        data = request.get_json()
        
        
        try:
            seller = SellerService.create_seller(
                name=data.get("name"),
                email=data.get("email"),
                password=data.get("password"),
                cnpj=data.get("cnpj"),
                celular=data.get("celular")
            )
            return jsonify({"mensagem": "Seller salvo com sucesso", "seller": seller.to_dict()}), 201
        except Exception as e:
            return jsonify({"erro": str(e)}), 400