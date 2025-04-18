from flask import Blueprint, request, jsonify
from app import db
from app.models.user import User
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token, jwt_required,
    get_jwt_identity
)

bcrypt = Bcrypt()
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Verificar si el correo electrónico ya está registrado
    if User.query.filter_by(email=data['email']).first():
        return jsonify(message="El correo electrónico ya está registrado"), 400

    # Verificar si el nombre de usuario ya está tomado
    if User.query.filter_by(username=data['username']).first():
        return jsonify(message="El nombre de usuario ya está tomado"), 400
    
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    # Crear nuevo usuario
    new_user = User(
        username=data['username'],
        email=data['email'],
        password=hashed_password,
        role=data.get('role', 'user')  # Default role is 'user'
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify(message="Usuario registrado correctamente"), 201
    except Exception as e:
        db.session.rollback()
        return jsonify(message="Error al registrar el usuario", error=str(e)), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Verificar si el email y la contraseña fueron proporcionados
    if not data.get('email') or not data.get('password'):
        return jsonify(message="Correo electrónico y contraseña son requeridos"), 400

    user = User.query.filter_by(email=data['email']).first()

    if user and bcrypt.check_password_hash(user.password, data['password']):
        # Crear token de acceso
        access_token = create_access_token(identity={
            'id': user.id,
            'username': user.username,
            'role': user.role
        })
        return jsonify(access_token=access_token), 200
    else:
        return jsonify(message="Credenciales inválidas"), 401
