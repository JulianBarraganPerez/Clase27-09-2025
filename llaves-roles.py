# instalar dependencias: pip install flask pyjwt cryptography

from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
# Llaves RSA (ejemplo)

with open("private.pem", "r") as f:
    PRIVATE_KEY = f.read()

with open("public.pem", "r") as f:
    PUBLIC_KEY = f.read()



# Usuarios simulados
usuarios = [
    {"nombre": "juan", "clave": "1234", "rol": "basico"},
    {"nombre": "ana", "clave": "5678", "rol": "admin"},
]

# Decorador de roles
def token_requerido(roles_permitidos):
    def decorador(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = None

            if "Authorization" in request.headers:
                auth_header = request.headers["Authorization"]
                if auth_header.startswith("Bearer "):
                    token = auth_header.split(" ")[1]

            if not token:
                return jsonify({"error": "Token requerido"}), 401

            try:
                data = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
                request.usuario = data

                if data.get("rol") not in roles_permitidos:
                    return jsonify({"error": "Acceso denegado (rol inválido)"}), 403

            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expirado"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Token inválido"}), 401

            return f(*args, **kwargs)
        return wrapper
    return decorador

# Endpoints
@app.route("/autenticacion", methods=["POST"])
def autenticacion():
    datos = request.json
    usuario = datos.get("usuario")
    clave = datos.get("clave")

    user = next((u for u in usuarios if u["nombre"] == usuario and u["clave"] == clave), None)

    if not user:
        return jsonify({"error": "Credenciales inválidas"}), 401

    payload = {
        "usuario": user["nombre"],
        "rol": user["rol"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }

    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    return jsonify({"token": token})

@app.route("/saludo", methods=["GET"])
@token_requerido(["basico", "admin"])
def saludo():
    usuario = request.usuario.get("usuario")
    rol = request.usuario.get("rol")
    return jsonify({"mensaje": f"Hola {usuario}, tu rol es {rol}"})

@app.route("/despido", methods=["GET"])
@token_requerido(["admin"])
def despido():
    usuario = request.usuario.get("usuario")
    return jsonify({"mensaje": f"Chao {usuario}, hasta pronto"})

if __name__ == "__main__":
    app.run(debug=True, port=5000)



