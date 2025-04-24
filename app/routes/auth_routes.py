from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, jwt_required,
    get_jwt_identity, create_refresh_token
)
from sqlalchemy.exc import SQLAlchemyError
from app import db, oauth
from app.models.user import User
import jwt
from functools import wraps

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# ----------------------------
# Decoradores y helpers
# ----------------------------
def auth0_required(f):
    """Decorator para endpoints que requieren autenticación con Auth0"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'Authorization' not in request.headers:
            return jsonify(message="Token de autorización faltante"), 401
            
        token = request.headers['Authorization'].split(' ')[1]
        try:
            jwt.decode(
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

# ----------------------------
# Rutas CRUD para Usuarios
# ----------------------------
@auth_bp.route('/users', methods=['POST'])
@jwt_required()
def create_user():
    """Crear un nuevo usuario (para administradores)"""
    try:
        data = request.get_json()
        
        # Validación básica
        if not data.get('email'):
            return jsonify({"error": "Email es requerido"}), 400
            
        # Verificar si el usuario ya existe
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"error": "El usuario ya existe"}), 409
            
        new_user = User(
            email=data['email'],
            username=data.get('username', data['email'].split('@')[0]),
            role=data.get('role', 'user')
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            "message": "Usuario creado",
            "user": {
                "id": new_user.id,
                "email": new_user.email,
                "role": new_user.role
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@auth_bp.route('/users/<string:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Obtener información de un usuario específico"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404
            
        return jsonify({
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "role": user.role,
            "auth0_id": user.auth0_id
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@auth_bp.route('/users/<string:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    """Actualizar información de usuario"""
    try:
        data = request.get_json()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404
            
        if data.get('email'):
            user.email = data['email']
        if data.get('username'):
            user.username = data['username']
        if data.get('role'):
            user.role = data['role']
            
        db.session.commit()
        
        return jsonify({
            "message": "Usuario actualizado",
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@auth_bp.route('/users/<string:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    """Eliminar un usuario"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404
            
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({"message": "Usuario eliminado"}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# ----------------------------
# Autenticación con Auth0
# ----------------------------
@auth_bp.route('/auth0/login', methods=['GET'])
def auth0_login():
    """Redirige al login de Auth0"""
    auth0 = oauth.auth0
    return auth0.authorize_redirect(
        redirect_uri=current_app.config['AUTH0_CALLBACK_URL'],
        audience=current_app.config['AUTH0_AUDIENCE']
    )

@auth_bp.route('/auth0/callback', methods=['GET'])
def auth0_callback():
    """Callback después del login exitoso con Auth0"""
    try:
        auth0 = oauth.auth0
        token = auth0.authorize_access_token()
        userinfo = token.get('userinfo')
        
        if not userinfo:
            return jsonify(message="No se pudo obtener la información del usuario"), 400

        # Buscar o crear usuario en nuestra base de datos
        user = User.query.filter_by(auth0_id=userinfo['sub']).first()
        
        if not user:
            user = User(
                auth0_id=userinfo['sub'],
                email=userinfo.get('email'),
                username=userinfo.get('nickname', userinfo.get('name', '').split('@')[0]),
                role='user'
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

        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role
            }
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error en callback de Auth0: {str(e)}")
        return jsonify(message="Error en el proceso de autenticación"), 500

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
    """Obtener perfil del usuario actual"""
    current_user = get_jwt_identity()
    user = User.query.get(current_user['id'])

    if not user:
        return jsonify(message="Usuario no encontrado"), 404

    return jsonify({
        'id': user.id,
        'email': user.email,
        'role': user.role,
        'auth0_id': user.auth0_id
    }), 200

@auth_bp.after_request
def after_request(response):
    """Limpieza después de cada request"""
    db.session.remove()
    return response