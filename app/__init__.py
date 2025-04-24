from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os
from authlib.integrations.flask_client import OAuth  
import sys
import authlib  

print("PYTHONPATH:", sys.path)
print("Authlib cargado desde:", authlib.__file__)

# Inicializar extensiones
db = SQLAlchemy()
bcrypt = Bcrypt()
migrate = Migrate()
jwt_manager = JWTManager()
oauth = OAuth()

load_dotenv()

def create_app():
    app = Flask(__name__)

    # Configuración básica
    app.config.from_object('app.config.Config')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'SQLALCHEMY_DATABASE_URI',
        'sqlite:///instance/kupula.db'
    )
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback_secret_key')
    app.config['JWT_SECRET_KEY'] = os.environ.get(
        'JWT_SECRET_KEY',
        app.config['SECRET_KEY']
    )

    # Configuración Auth0
    app.config['AUTH0_DOMAIN'] = os.environ.get('AUTH0_DOMAIN')
    app.config['AUTH0_CLIENT_ID'] = os.environ.get('AUTH0_CLIENT_ID')
    app.config['AUTH0_CLIENT_SECRET'] = os.environ.get('AUTH0_CLIENT_SECRET')
    app.config['AUTH0_CALLBACK_URL'] = os.environ.get('AUTH0_CALLBACK_URL')
    app.config['AUTH0_AUDIENCE'] = os.environ.get('AUTH0_AUDIENCE')

    # CORS para rango 5173–5178
    allowed_origins = [f"http://localhost:{port}" for port in range(5173, 5179)]
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": allowed_origins,
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"]
            }
        }
    )

    if __name__ == "__main__":
     app.run(debug=True)

    # Inicializar extensiones
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)
    jwt_manager.init_app(app)

    # Registrar OAuth de Authlib
    oauth.register(
        'auth0',
        client_id=app.config['AUTH0_CLIENT_ID'],
        client_secret=app.config['AUTH0_CLIENT_SECRET'],
        api_base_url=f"https://{app.config['AUTH0_DOMAIN']}",
        access_token_url=f"https://{app.config['AUTH0_DOMAIN']}/oauth/token",
        authorize_url=f"https://{app.config['AUTH0_DOMAIN']}/authorize",
        client_kwargs={
            'scope': 'openid profile email',
            'audience': app.config['AUTH0_AUDIENCE']
        }
    )

    # Registrar blueprints (importarlos aquí para evitar circular imports)
    from app.routes.auth_routes import auth_bp
    from app.routes.cursos import cursos_bp
    from app.routes.test_routes import test_bp
    from app.routes.contacto_routes import contacto_bp

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(cursos_bp, url_prefix='/api/cursos')
    app.register_blueprint(test_bp, url_prefix='/api/test')
    app.register_blueprint(contacto_bp, url_prefix='/api/contacto')

    return app
    
