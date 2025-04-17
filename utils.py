# app/utils.py
from flask_mail import Message
from app import mail
from flask import current_app

def send_verification_email(email, token):
    msg = Message('Verify your email',
                  recipients=[email])
    link = f"{current_app.config['BASE_URL']}/api/auth/verify_email/{token}"
    msg.body = f'Click the link to verify your email: {link}'
    mail.send(msg)

def send_password_reset_email(email, token):
    msg = Message('Reset your password',
                  recipients=[email])
    link = f"{current_app.config['BASE_URL']}/reset-password/{token}"  # <- frontend aquí
    msg.body = f'Click the link to reset your password: {link}'
    mail.send(msg)
