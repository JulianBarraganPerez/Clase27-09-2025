# instalar dependencias: pip install flask pyjwt

from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

# Llave privada y pública simuladas
PRIVATE_KEY = "mi_clave_privada_y_segura"
PUBLIC_KEY = PRIVATE_KEY 

# Usuarios simulados
usuarios = [
    {"nombre": "juan", "clave": "1234", "rol": "basico"},
    {"nombre": "ana", "clave": "5678", "rol": "admin"},
]

# Función para validar token
def token_requerido(roles_permitidos):
    def decorador(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = None

            # Extraer token del header
            if "Authorization" in request.headers:
                auth_header = request.headers["Authorization"]
                if auth_header.startswith("Bearer "):
                    token = auth_header.split(" ")[1]

            if not token:
                return jsonify({"error": "Token requerido"}), 401

            try:
                # Decodificar y validar el JWT
                data = jwt.decode(token, PUBLIC_KEY, algorithms=["HS256"])
                request.usuario = data

                # Validar rol
                if data.get("rol") not in roles_permitidos:
                    return jsonify({"error": "Acceso denegado (rol inválido)"}), 403

            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expirado"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Token inválido"}), 401

            return f(*args, **kwargs)

        return wrapper
    return decorador


# Endpoint de autenticación
@app.route("/autenticacion", methods=["POST"])
def autenticacion():
    datos = request.json
    usuario = datos.get("usuario")
    clave = datos.get("clave")

    # Validar usuario en array simulado
    user = next((u for u in usuarios if u["nombre"] == usuario and u["clave"] == clave), None)

    if not user:
        return jsonify({"error": "Credenciales inválidas"}), 401

    # Claims con expiración (ej: 1 hora)
    payload = {
        "usuario": user["nombre"],
        "rol": user["rol"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }

    # Firmar token con la clave privada
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="HS256")

    return jsonify({"token": token})


# Endpoint /saludo (accesible por basico y admin)
@app.route("/saludo", methods=["GET"])
@token_requerido(["basico", "admin"])
def saludo():
    usuario = request.usuario.get("usuario")
    rol = request.usuario.get("rol")
    return jsonify({"mensaje": f"Hola {usuario}, tu rol es {rol}"})


# Endpoint /despido (solo admin)
@app.route("/despido", methods=["GET"])
@token_requerido(["admin"])
def despido():
    usuario = request.usuario.get("usuario")
    return jsonify({"mensaje": f"Chao {usuario}, hasta pronto"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)


