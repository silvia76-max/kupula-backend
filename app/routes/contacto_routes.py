@contacto_bp.route('', methods=['POST'])
def crear_contacto():
    if request.method == 'OPTIONS':
        return jsonify({}), 200 

    try:
        # Extraer datos del cuerpo de la solicitud
        data = request.get_json()

        # Validar que todos los campos obligatorios estén presentes
        required_fields = ['nombre', 'email', 'mensaje']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Faltan campos obligatorios"}), 400

        # Crear un nuevo registro en la base de datos
        nuevo_contacto = Contacto(
            nombre=data['nombre'],
            email=data['email'],
            mensaje=data['mensaje']
        )
        db.session.add(nuevo_contacto)
        db.session.commit()

        # Devolver una respuesta exitosa
        return jsonify({
            "status": "success",
            "message": "Mensaje recibido",
            "data": {
                "id": nuevo_contacto.id,
                "nombre": nuevo_contacto.nombre,
                "email": nuevo_contacto.email,
                "mensaje": nuevo_contacto.mensaje,
                "fecha_creacion": nuevo_contacto.fecha_creacion.isoformat()
            }
        }), 201

    except Exception as e:
        # Revertir la transacción en caso de error
        db.session.rollback()
        return jsonify({"error": str(e)}), 500