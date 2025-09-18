import os
import random
from twilio.rest import Client

def generate_code():
    return str(random.randint(1000, 9999))

def mock_send_whatsapp(celular: str, codigo: str):
    print(f"[MOCK] WhatsApp para {celular} com código {codigo}")
    return "mocked-sid"

def real_send_whatsapp(celular: str, codigo: str):
    """
    Envia o código de ativação via WhatsApp usando Twilio.
    O celular deve estar no formato internacional: +55DDDNÚMERO
    """
    account_sid = os.getenv("TWILIO_SID")
    auth_token = os.getenv("TWILIO_AUTH")
    twilio_number = os.getenv("TWILIO_NUMBER")

    client = Client(account_sid, auth_token)

    mensagem = f"Seu código de ativação é: {codigo}"

    message = client.messages.create(
        from_=f"whatsapp:{twilio_number}",
        body=mensagem,
        to=f"whatsapp:{celular}"
    )
    return message.sid

def send_whatsapp(celular: str, codigo: str):
    use_mock = os.getenv("USE_MOCK_WHATSAPP", "true").lower() == "true"
    if use_mock:
        return mock_send_whatsapp(celular, codigo)
    return real_send_whatsapp(celular, codigo)
