import os

class Config:
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///kupula.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv('SECRET_KEY', 'supersecreto')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwtsecreto')

    
MAIL_SERVER = 'smtp.gmail.com'  # Cambia a tu servidor
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'your-email@gmail.com'
MAIL_PASSWORD = 'your-email-password'
MAIL_DEFAULT_SENDER = 'your-email@gmail.com'
BASE_URL = 'http://localhost:5000'
