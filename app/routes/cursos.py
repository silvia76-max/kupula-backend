from flask import Blueprint, jsonify
from app.models.curso import Curso
from app import db

cursos_bp = Blueprint('cursos', __name__)

@cursos_bp.route('/', methods=['GET'])
def get_cursos():
    cursos = Curso.query.all()
    resultado = []
    for curso in cursos:
        resultado.append({
            'id': curso.id,
            'titulo': curso.titulo,
            'descripcion': curso.descripcion,
            'duracion': curso.duracion
        })
    return jsonify(resultado)
