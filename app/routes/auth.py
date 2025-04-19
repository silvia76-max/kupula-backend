from flask import Blueprint, request, jsonify
from flask_bcrypt import Bcrypt
from app import db
from flask_jwt_extended import create_access_token, check_password_hash, jwt_required, get_jwt_identity
from app.models.User import User # type: ignore
from utils import send_verification_email, send_password_reset_email
import uuid

bcrypt = Bcrypt()

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validar campos (username y email)
    if User.query.filter_by(email=data['email']).first():
        return jsonify(message="Email already exists"), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify(message="Username already taken"), 400
    
    # Crear nuevo usuario
    new_user = User(
        username=data['username'],
        email=data['email']
    )
    new_user.set_password(data['password'])
    
    # Generar un token de verificación de email
    verification_token = str(uuid.uuid4())
    new_user.email_confirmation_token = verification_token
    
    db.session.add(new_user)
    db.session.commit()
    
    # Enviar el correo de verificación (usando un helper)
    send_verification_email(new_user.email, verification_token)

    return jsonify(message="User registered, please check your email to verify your account"), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify(message="Email and password are required"), 400
    
    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify(message="Invalid email or password"), 401

    if not check_password_hash(user.password_hash, data['password']):
        return jsonify(message="Invalid email or password"), 401

    # Comprobar si el email ha sido verificado
    if not user.email_confirmed:
        return jsonify(message="Please verify your email before logging in"), 403

    # Crear token JWT
    access_token = create_access_token(identity=user.id) 
    
    return jsonify(access_token=access_token, username=user.username, role=user.role), 200

@auth_bp.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    user = User.query.filter_by(email_confirmation_token=token).first()
    
    if not user:
        return jsonify(message="Invalid or expired token"), 400
    
    user.email_confirmed = True
    user.email_confirmation_token = None
    db.session.commit()

    return jsonify(message="Email verified successfully"), 200

@auth_bp.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    
    # Verificar si el email existe
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify(message="Email not found"), 404
    
    # Generar token de reset
    reset_token = str(uuid.uuid4())
    user.email_confirmation_token = reset_token
    user.password_reset_token = reset_token
    db.session.commit()
    
    # Enviar el correo de reset de contraseña
    send_password_reset_email(user.email, reset_token)
    
    return jsonify(message="Password reset email sent"), 200

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()  # Esto asegura que solo los usuarios autenticados puedan acceder
def profile():
    # Obtener el id del usuario desde el token JWT
    user_id = get_jwt_identity()

    # Buscar al usuario en la base de datos usando el ID
    user = User.query.get(user_id)

    if not user:
        return jsonify(message="User not found"), 404

    # Devolver los datos del usuario (puedes personalizar lo que deseas mostrar)
    user_data = {
        "username": user.username,
        "email": user.email,
        "email_confirmed": user.email_confirmed,
        "role": user.role,
        # Evitar mostrar la contraseña hash
    }

    return jsonify(user_data), 200
