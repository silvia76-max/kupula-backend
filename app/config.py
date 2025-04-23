import os
from os import environ
from dotenv import load_dotenv

load_dotenv()

class Config:
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///kupula.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv('SECRET_KEY', 'supersecreto')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwtsecreto')
    AUTH0_DOMAIN = environ.get('AUTH0_DOMAIN')
    AUTH0_CLIENT_ID = environ.get('AUTH0_CLIENT_ID')
    AUTH0_CLIENT_SECRET = environ.get('AUTH0_CLIENT_SECRET')
    AUTH0_CALLBACK_URL = environ.get('AUTH0_CALLBACK_URL')

    
MAIL_SERVER = 'smtp.gmail.com'  # Cambia a tu servidor
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'your-email@gmail.com'
MAIL_PASSWORD = 'your-email-password'
MAIL_DEFAULT_SENDER = 'your-email@gmail.com'
BASE_URL = 'http://localhost:5000'
