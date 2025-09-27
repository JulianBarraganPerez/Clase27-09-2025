# instalar dependencias: pip install flask pyjwt cryptography

from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
# Llaves RSA (ejemplo)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAL7H5ECyx4F7IUK84z2MTmDPB3Q+3PyRjPlYhV9BrNoKQ0TS0BBp
dCKl72xz3NAY5cPPo7go+xE4LtNEbbhjYdUCAwEAAQJALjKXMK21toUim1ZqvUOw
Aepuwk7v0SBxlD7Kc1lTSvUxi32a92nBbMVhYVD4RZVZEnE7Vj4i9Wq9Q35s6DYz
+QIhAPQjEK2AOrDG5dMJHTi+03Wg8Yv2G6DKSg9XsZGoo0flAiEAwwf5FXjOWHsp
1Bj1fXgh1oOlZ8raYw1cUlUTlU2rT0MCIQDLN26TzMe8blzUlWzqZgVqkZaQSEpH
CSjDlLZ3T/Rp4QIhAL8NMyNQ7KZ4fY9VEzM56gr1N54Q3nAJfdAvF3qPBzT9AiEA
pm9WBru+ewStcvQEmUReGLG4VCF3OHtxrgH3FoGhOow=
-----END RSA PRIVATE KEY-----"""

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL7H5ECyx4F7IUK84z2MTmDPB3Q+3PyR
jPlYhV9BrNoKQ0TS0BBpdCKl72xz3NAY5cPPo7go+xE4LtNEbbhjYdUCAwEAAQ==
-----END PUBLIC KEY-----"""

# Usuarios simulados
usuarios = [
    {"nombre": "juan", "clave": "1234", "rol": "basico"},
    {"nombre": "ana", "clave": "5678", "rol": "admin"},
]

# ==========================
# Decorador para validar token
# ==========================
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
                # Decodificar con llave pública
                data = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
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

    # Claims con expiración (ej: 2 horas)
    payload = {
        "usuario": user["nombre"],
        "rol": user["rol"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }

    # Firmar token con la llave privada (RSA)
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

    return jsonify({"token": token})

# Endpoint /saludo (basico y admin)
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

# Run
if __name__ == "__main__":
    app.run(debug=True, port=5000)


