from flask import Blueprint, request, jsonify
from flask_cors import CORS
from app import db, bcrypt
from app.models.user import User
from flask_jwt_extended import (
    create_access_token, jwt_required,
    get_jwt_identity, create_refresh_token
)
from sqlalchemy.exc import SQLAlchemyError
import re

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
CORS(auth_bp, supports_credentials=True)


def validate_email(email):
    """Valida el formato del email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

def validate_password(password):
    """Valida que la contraseña tenga al menos 8 caracteres"""
    if len(password) < 8:
        return False
    # Validación adicional de la contraseña (al menos una letra mayúscula, al menos un número)
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True



@auth_bp.route('/register', methods=['POST','OPTIONS'])
@Cors() # type: ignore
def register():
    print("\n===== DATOS DE LA PETICIÓN =====")
    print("Método:", request.method)
    print("Headers:", dict(request.headers))
    print("JSON recibido:", request.get_json())
    print("Datos brutos:", request.data)
    print("===============================\n")
    data = request.get_json()

    # Validaciones básicas
    required_fields = ['username', 'email', 'password']
    if not all(field in data for field in required_fields):
        return jsonify(message="Todos los campos son requeridos"), 400

    if not validate_email(data['email']):
        return jsonify(message="Formato de email inválido"), 400

    if not validate_password(data['password']):
        return jsonify(message="La contraseña debe tener al menos 8 caracteres, una letra mayúscula y un número"), 400

    # Verificar existencia de usuario
    if User.query.filter(db.or_(User.email == data['email'], User.username == data['username'])).first():
        return jsonify(message="Email o nombre de usuario ya registrados"), 409  # 409 Conflict

    try:
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        new_user = User(
            username=data['username'],
            email=data['email'],
            password=hashed_password,
            role=data.get('role', 'user')
        )

        db.session.add(new_user)
        db.session.commit()

        # Crear token inmediatamente después del registro
        access_token = create_access_token(identity={
            'id': new_user.id,
            'username': new_user.username,
            'role': new_user.role
        })
        refresh_token = create_refresh_token(identity={
            'id': new_user.id
        })

        return jsonify(
            message="Usuario registrado correctamente",
            access_token=access_token,
            refresh_token=refresh_token
        ), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify(message="Error en la base de datos", error=str(e)), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify(message="Email y contraseña son requeridos"), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify(message="Credenciales inválidas"), 401

    # Crear tokens
    access_token = create_access_token(identity={
        'id': user.id,
        'username': user.username,
        'role': user.role
    })
    refresh_token = create_refresh_token(identity={
        'id': user.id
    })

    return jsonify(
        access_token=access_token,
        refresh_token=refresh_token,
        user={
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        }
    ), 200

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user)
    return jsonify(access_token=new_token), 200

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    user = User.query.get(current_user['id'])

    if not user:
        return jsonify(message="Usuario no encontrado"), 404

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'created_at': user.created_at.isoformat() if user.created_at else None
    }), 200
@auth_bp.route('/check_db', methods=['GET'])
def check_db():
    try:
        # Realiza una consulta simple a la base de datos
        db.session.execute('SELECT 1')
        return jsonify(message="Conexión a la base de datos exitosa"), 200
    except Exception as e:
        return jsonify(message=f"Error al conectar a la base de datos: {str(e)}"), 500