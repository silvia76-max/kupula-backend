# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv 
import os

# Inicializar extensiones (fuera de create_app para poder importarlas en otros archivos)
db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()
migrate = Migrate()
load_dotenv()

def create_app():
    app = Flask(__name__)
    
    # Configuración básica
    app.config.from_object('app.config.Config')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kupula.db'
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'tu_clave_secreta_por_defecto'
    app.config['JWT_SECRET_KEY'] = app.config['SECRET_KEY']  # Importante para JWT
    
    # Habilitar CORS para toda la aplicación o rutas específicas
    CORS(app, resources={
        r"/api/*": {
            "origins": "http://localhost:5173",
            "supports_credentials": True
        }
    })
    
    # Inicializar extensiones con la app
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)  # Migrate necesita la app y db
    
    # Importar blueprints aquí para evitar importaciones circulares
    from app.routes.auth_routes import auth_bp
    from app.routes.cursos import cursos_bp
    
    # Registrar blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(cursos_bp, url_prefix='/api/cursos')
    
    return app