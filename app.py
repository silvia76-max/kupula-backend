from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
from functools import wraps

# Inicializar las extensiones
db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()

# Crear la aplicación
def create_app():
    app = Flask(__name__)
    CORS(app)  # Habilitar CORS para el frontend

    # Configuración de la app
    app.config.from_object('app.config.Config')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kupula.db'
    app.config['SECRET_KEY'] = 'tu_secreto'  # Clave secreta para firmar el token JWT

    # Inicializar las extensiones
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)

    # Registrar Blueprints
    from app.routes.cursos import cursos_bp
    from app.routes.auth_routes import auth_bp
    app.register_blueprint(cursos_bp, url_prefix='/api/cursos')
    app.register_blueprint(auth_bp, url_prefix='/api/auth')

    # Rutas de la API (dentro de create_app)
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        # Buscar el usuario en la base de datos
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            # Crear un token JWT
            token = create_access_token(identity=user.id)
            return jsonify({'access_token': token}), 200
        else:
            return jsonify({'message': 'Credenciales incorrectas'}), 401

    @app.route('/api/auth/profile', methods=['GET'])
    @jwt_required()
    def profile():
        current_user = get_jwt_identity()  # Obtener el ID del usuario desde el token
        user = User.query.get(current_user)  # Buscar al usuario en la base de datos

        if not user:
            return jsonify({'message': 'Usuario no encontrado'}), 404

        return jsonify({
            'username': user.username,
            'email': user.email,
            'role': 'user'  # Ajusta el rol según tu modelo
        }), 200

    return app

# Modelo de Usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

# Función para verificar el token JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]  # Obtener el token
        if not token:
            return jsonify({'message': 'Token es necesario'}), 401

        try:
            # Verificar el token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user_id']
        except:
            return jsonify({'message': 'Token es inválido'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
