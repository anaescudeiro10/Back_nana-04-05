import re
import jwt
import datetime
import smtplib
import random
import string
import os
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash


def verificar_senha(senha):
    """Valida a complexidade da senha."""
    if len(senha) < 8:
        return "A senha deve ter no mínimo 8 caracteres."
    if not re.search(r"[A-Z]", senha):
        return "A senha precisa de pelo menos uma letra maiúscula."
    if not re.search(r"[0-9]", senha):
        return "A senha precisa de pelo menos um número."
    if not re.search(r"[@$!%*?&]", senha):
        return "A senha precisa de um caractere especial (@$!%*?&)."
    return None

def verificar_reuso_senha(id_usuario, nova_senha, cursor):
    """Verifica se a nova senha já foi usada nas últimas 3 trocas."""
    # O FIRST 3 é específico do Firebird
    cursor.execute("""
        SELECT FIRST 3 senha_antiga
        FROM HISTORICO_SENHAS
        WHERE id_usuario = ?
        ORDER BY id_historico DESC 
    """, (id_usuario,))
    # Nota: Use uma coluna de ID ou Data para garantir que sejam as ÚLTIMAS 3

    historico = cursor.fetchall()
    for registro in historico:
        if checar_senha(nova_senha, registro[0]):
            return True
    return False


def criptografar(senha):
    # O método pbkdf2:sha256 é o padrão seguro do Werkzeug
    return generate_password_hash(senha)


def checar_senha(senha_digitada, senha_hash):
    if not senha_hash:
        return False
    return check_password_hash(senha_hash, senha_digitada)


# --- COMUNICAÇÃO E TOKENS ---

def gerar_codigo():
    return ''.join(random.choices(string.digits, k=6))

def enviando_email(destinatario, assunto, corpo_html):
    try:
        email_origem = "ana.escudeiro5@gmail.com"
        senha_aplicativo = "wihsug-syrTe3-suqwov"

        print("[DEBUG] Iniciando envio de email...")

        msg = EmailMessage()
        msg['Subject'] = assunto
        msg['From'] = email_origem
        msg['To'] = destinatario
        msg.add_alternative(corpo_html, subtype='html')

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            print("[DEBUG] Conectado ao SMTP")
            smtp.login(email_origem, senha_aplicativo)
            print("[DEBUG] Login realizado")
            smtp.send_message(msg)
            print("[DEBUG] Email enviado com sucesso")

        return True

    except Exception as e:
        print(f"[ERRO EMAIL] {e}")
        return False


def gerar_token(id_usuario):
    # Import local para evitar importação circular
    from main import app
    payload = {
        "id_usuario": id_usuario,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")


def remover_bearer(token):
    if token and token.startswith("Bearer "):
        return token.split(" ")[1]
    return token


# --- LÓGICA DE BANCO DE DADOS ---

def verificar_reuso_senha(id_usuario, nova_senha, cursor):
    """
    Verifica se a nova senha já foi usada nos últimos 3 registros de histórico.
    Retorna True se a senha JÁ EXISTE (reuso proibido).
    """
    cursor.execute("""
        SELECT FIRST 3 senha_antiga
        FROM HISTORICO_SENHAS
        WHERE id_usuario = ?
        ORDER BY data_alteracao DESC
    """, (id_usuario,))

    historico = cursor.fetchall()

    for registro in historico:
        # registro[0] contém o hash da senha antiga
        if checar_senha(nova_senha, registro[0]):
            return True

    return False