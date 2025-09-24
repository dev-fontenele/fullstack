from flask import Flask, jsonify, send_from_directory, request, redirect, url_for
from src.Application.Controllers.user_controller import UserController
from src.Application.Controllers.seller_controller import SellerController 


def init_routes(app):
    @app.route("/")
    def index_page():
        return send_from_directory("frontend", "index.html")

    @app.route("/login_page", methods=["GET"])
    def login_page():
        return send_from_directory("frontend", "login.html")
    @app.route("/cadastro_page", methods=["GET"])
    def cadastro_page():
        return send_from_directory("frontend", "cadastro.html")
    @app.route("/user", methods=["POST"])
    def register_user_route():
        return UserController.register_user()
    
    @app.route("/login", methods=["POST"])
    def login_user():
        return UserController.login_user()

    @app.route("/css/<path:filename>")
    def css_files(filename):
        return send_from_directory("frontend/css", filename)

    @app.route("/images/<path:filename>")
    def images_files(filename):
        return send_from_directory("frontend/images", filename)

    @app.route("/health", methods=["GET"])
    def health_check():
        return jsonify({"status": "ok"}), 200

    @app.route("/api/sellers", methods=["POST"])
    def register_seller_route():
        return SellerController.register_seller()

    @app.route("/api/sellers/activate", methods=["POST"])
    def activate_seller_route():
        return SellerController.activate_seller()