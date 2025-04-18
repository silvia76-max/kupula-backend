# app/__init__.py
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
from functools import wraps

# Inicializar extensiones
db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()

def create_app():
    app = Flask(__name__)
    CORS(app)

    app.config.from_object('app.config.Config')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kupula.db'
    app.config['SECRET_KEY'] = 'tu_secreto'

    db.init_app(app)
    migrate = Migrate(app, db)
    bcrypt.init_app(app)
    jwt.init_app(app)

    # Importar y registrar blueprints
    from app.routes.cursos import cursos_bp
    from app.routes.auth_routes import auth_bp
    app.register_blueprint(cursos_bp, url_prefix='/api/cursos')
    app.register_blueprint(auth_bp, url_prefix='/api/auth')

    return app
