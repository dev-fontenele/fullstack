import random
import datetime
from src.Infrastructure.Model.user import User
from src.config.data_base import db
# from twilio.rest import Client # Você vai precisar desta linha para integrar com a Twilio
# from your_twilio_config import TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_NUMBER

class SellerService:
    @staticmethod
    def create_seller(name, email, password, cnpj, celular):
        activation_code = str(random.randint(1000, 9999))
        expiration_time = datetime.datetime.now() + datetime.timedelta(minutes=15)

        
        new_seller = User(
            name=name,
            email=email,
            password=password, 
            cnpj=cnpj,
            celular=celular,
            status="inativo" 
        )
        
        
        db.session.add(new_seller)
        db.session.commit()

        # 4. Enviar o código de ativação (aqui é onde a Twilio entra)
        # O mock pode ser implementado aqui para testes
        # send_whatsapp(celular, activation_code)

        return new_seller