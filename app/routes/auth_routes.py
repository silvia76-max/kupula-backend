from flask import Blueprint, request, jsonify, current_app
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from app import db, bcrypt
from app.models.user import User
from flask_jwt_extended import (
    create_access_token, jwt_required,
    get_jwt_identity, create_refresh_token
)
from sqlalchemy.exc import SQLAlchemyError
import re
from sqlalchemy import or_
import jwt
from functools import wraps
from flask import current_app
from app import oauth

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Función para obtener la configuración de Auth0
def get_auth0():
      return oauth.auth0

def validate_email(email):
    """Valida el formato del email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

def validate_password(password):
    """Valida que la contraseña tenga al menos 8 caracteres"""
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True

def auth0_required(f):
    """Decorator para endpoints que requieren autenticación con Auth0"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'Authorization' not in request.headers:
            return jsonify(message="Token de autorización faltante"), 401
            
        token = request.headers['Authorization'].split(' ')[1]
        try:
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256'],
                options={'verify_aud': False}
            )
        except jwt.ExpiredSignatureError:
            return jsonify(message="Token expirado"), 401
        except jwt.InvalidTokenError:
            return jsonify(message="Token inválido"), 401
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/auth0/login', methods=['GET'])
def auth0_login():
    """Redirige al login de Auth0"""
    auth0 = get_auth0()
    return auth0.authorize_redirect(
        redirect_uri=current_app.config['AUTH0_CALLBACK_URL'],
        audience=current_app.config['AUTH0_AUDIENCE']
    )

@auth_bp.route('/auth0/callback', methods=['GET'])
def auth0_callback():
    """Callback después del login exitoso con Auth0"""
    try:
        auth0 = get_auth0()
        token = auth0.authorize_access_token()
        userinfo = token.get('userinfo')
        
        if not userinfo:
            return jsonify(message="No se pudo obtener la información del usuario"), 400

        # Buscar o crear usuario en nuestra base de datos
        user = User.query.filter_by(auth0_id=userinfo['sub']).first()
        
        if not user:
            user = User(
                auth0_id=userinfo['sub'],
                email=userinfo.get('email', userinfo['name']),
                username=userinfo.get('nickname', userinfo['name'].split('@')[0]),
                role='user',
                email_verified=userinfo.get('email_verified', False)
            )
            db.session.add(user)
            db.session.commit()

        access_token = create_access_token(identity={
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'auth0_id': user.auth0_id
        })
        refresh_token = create_refresh_token(identity={
            'id': user.id,
            'auth0_id': user.auth0_id
        })

        return jsonify(
            access_token=access_token,
            refresh_token=refresh_token,
            user={
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'auth0_id': user.auth0_id
            }
        ), 200

    except Exception as e:
        current_app.logger.error(f"Error en callback de Auth0: {str(e)}")
        return jsonify(message="Error en el proceso de autenticación"), 500

@auth_bp.after_request
def after_request(response):
    """Limpieza después de cada request"""
    db.session.remove()
    return response

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refrescar token JWT"""
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user)
    return jsonify(access_token=new_token), 200

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    """Obtener perfil del usuario"""
    current_user = get_jwt_identity()
    user = User.query.get(current_user['id'])

    if not user:
        return jsonify(message="Usuario no encontrado"), 404

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'auth0_id': getattr(user, 'auth0_id', None)  # Compatible con usuarios locales y Auth0
    }), 200

@auth_bp.route('/check_db', methods=['GET'])
def check_db():
    """Verificar conexión a la base de datos"""
    try:
        db.session.execute('SELECT 1')
        return jsonify(message="Conexión a la base de datos exitosa"), 200
    except Exception as e:
        return jsonify(message=f"Error al conectar a la base de datos: {str(e)}"), 500
@auth_bp.route('/db-create', methods=['POST'])
def db_create():
    print(">> db-create llamado, payload:", request.json)
    data = request.json
    # valida email y contraseña…
    if not validate_email(data.get('email')):
        return jsonify(message="Email inválido"), 400
    if not validate_password(data.get('password')):
        return jsonify(message="Contraseña inválida"), 400

    pw_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(email=data['email'], username=data['name'], password=pw_hash)

    try:
        db.session.add(user)
        db.session.commit()
        return jsonify(user_id=str(user.id)), 201
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify(message="Usuario ya existe"), 409

@auth_bp.route('/db-login', methods=['POST'])
def db_login():
    print(">> db-login llamado, payload:", request.json)
    data = request.json
    user = User.query.filter_by(email=data.get('email')).first()
    if user and bcrypt.check_password_hash(user.password, data.get('password')):
        return jsonify(user_id=str(user.id), email=user.email), 200
    return jsonify(message="Credenciales inválidas"), 401
