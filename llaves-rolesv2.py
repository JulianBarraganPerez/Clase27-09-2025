# instalar dependencias: pip install flask pyjwt cryptography

from flask import Flask, request, jsonify
import jwt
import datetime
import uuid
from functools import wraps

app = Flask(__name__)

with open("private.pem", "r") as f:
    PRIVATE_KEY = f.read()

with open("public.pem", "r") as f:
    PUBLIC_KEY = f.read()

# --- Simulación de usuarios y clientes ---
usuarios = [
    {"nombre": "juan", "clave": "1234", "rol": "basico"},
    {"nombre": "ana", "clave": "5678", "rol": "admin"},
]

clientes = [
    {"client_id": "micro1", "client_secret": "abcd1234"}
]

# Guardar refresh tokens
refresh_tokens = {}

# --- Decorador de validación ---
def token_requerido(scopes_permitidos):
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

                # Validar scopes
                token_scopes = data.get("scope", "").split()
                if not any(s in token_scopes for s in scopes_permitidos):
                    return jsonify({"error": "Acceso denegado (scope inválido)"}), 403

            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expirado"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Token inválido"}), 401

            return f(*args, **kwargs)
        return wrapper
    return decorador

# --- Endpoints OAuth2 ---

# 1. Client Credentials Grant
@app.route("/token/client", methods=["POST"])
def client_credentials():
    datos = request.json
    cid = datos.get("client_id")
    secret = datos.get("client_secret")

    client = next((c for c in clientes if c["client_id"] == cid and c["client_secret"] == secret), None)
    if not client:
        return jsonify({"error": "Credenciales de cliente inválidas"}), 401

    payload = {
        "client_id": cid,
        "scope": "service.read service.write",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    access_token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    return jsonify({"access_token": access_token, "token_type": "Bearer", "expires_in": 1800})

# 2. Password Grant con Refresh Token
@app.route("/token/user", methods=["POST"])
def user_login():
    datos = request.json
    usuario = datos.get("usuario")
    clave = datos.get("clave")

    user = next((u for u in usuarios if u["nombre"] == usuario and u["clave"] == clave), None)
    if not user:
        return jsonify({"error": "Credenciales inválidas"}), 401

    payload = {
        "usuario": user["nombre"],
        "rol": user["rol"],
        "scope": "user.read user.write",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }
    access_token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

    refresh_token = str(uuid.uuid4())
    refresh_tokens[refresh_token] = usuario

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": 900
    })

# 3. Refresh Token
@app.route("/token/refresh", methods=["POST"])
def refresh():
    datos = request.json
    rtoken = datos.get("refresh_token")

    usuario = refresh_tokens.get(rtoken)
    if not usuario:
        return jsonify({"error": "Refresh token inválido"}), 401

    user = next((u for u in usuarios if u["nombre"] == usuario), None)

    payload = {
        "usuario": user["nombre"],
        "rol": user["rol"],
        "scope": "user.read user.write",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }
    access_token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    return jsonify({"access_token": access_token, "token_type": "Bearer", "expires_in": 900})

# --- Endpoints protegidos ---
@app.route("/saludo", methods=["GET"])
@token_requerido(["user.read", "service.read"])
def saludo():
    return jsonify({"mensaje": f"Hola {request.usuario.get('usuario', 'microservicio')}"})

@app.route("/despido", methods=["GET"])
@token_requerido(["user.write", "service.write"])
def despido():
    return jsonify({"mensaje": "Chao, hasta pronto"})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
