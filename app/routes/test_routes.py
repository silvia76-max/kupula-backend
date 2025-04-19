from flask import Blueprint, jsonify

test_bp = Blueprint('test', __name__)

@test_bp.route('/ping', methods=['GET'])
def ping():
    return jsonify({"message": "pong desde Blueprint!"})
