# instalar dependencias: pip install flask pyjwt cryptography
from flask import Flask, request, jsonify
import jwt
import datetime
import uuid
from functools import wraps
import secrets

app = Flask(__name__)

# ------------------------------
# Cargar llaves RSA
# ------------------------------
with open("private.pem", "r") as f:
    PRIVATE_KEY = f.read()

with open("public.pem", "r") as f:
    PUBLIC_KEY = f.read()

# ------------------------------
# Simulación de usuarios y clientes
# ------------------------------
usuarios = [
    {"nombre": "juan", "clave": "1234", "rol": "basico"},
    {"nombre": "ana", "clave": "5678", "rol": "admin"},
]

clientes = [
    {"client_id": "micro1", "client_secret": "abcd1234"}
]

# ------------------------------
# Scopes definidos formalmente
# ------------------------------
SCOPES = {
    "service.read": "Permite leer información entre servicios (Client Credentials)",
    "service.write": "Permite escribir información entre servicios (Client Credentials)",
    "user.read": "Permite leer información de usuario final (Password Grant)",
    "user.write": "Permite modificar información de usuario final (Password Grant)"
}

# ------------------------------
# Almacenamiento de Refresh Tokens
# ------------------------------
refresh_tokens = {}
active_user_tokens = {}
active_client_tokens = {}

test_data = {}
# ------------------------------
# Middleware para exigir HTTPS
# ------------------------------
@app.before_request
def verificar_https():
    if not request.is_secure:
        return jsonify({
            "error": "Conexión no segura. Los tokens solo se transmiten por HTTPS."
        }), 403

# ------------------------------
# Decorador para validar Access Tokens
# ------------------------------
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

                if "usuario" in data:  # token emitido para un usuario
                    usuario = data["usuario"]
                    if active_user_tokens.get(usuario) != token:
                        return jsonify({"error": "Token reemplazado o inválido"}), 401

                elif "client_id" in data:  # token emitido para un cliente
                    cid = data["client_id"]
                    if active_client_tokens.get(cid) != token:
                        return jsonify({"error": "Token reemplazado o inválido"}), 401

                # Validar que al menos un scope permitido esté en el token
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

@app.route("/prueba", methods=["GET"])
def prueba_rtokens():
    return refresh_tokens

@app.route("/prueba/tokensC", methods=["GET"])
def prueba_rtokens_c():
    return active_user_tokens

@app.route("/data", methods=["GET"])
def prueba_data():
    return test_data


# ------------------------------
# Endpoint: Client Credentials Grant
# ------------------------------
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
    active_client_tokens[cid] = access_token

    refresh_token = secrets.token_urlsafe(64)
    refresh_tokens[cid] = refresh_token

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 1800,
        "scope": "service.read service.write",
        "refresh_token":refresh_token
    })

# ------------------------------
# Endpoint: Password Grant (usuario final) + Refresh Token
# ------------------------------
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
    active_user_tokens[usuario] = access_token

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": 900,
        "scope": "user.read user.write"
    })

# ------------------------------
# Endpoint: Refresh Token
# ------------------------------
@app.route("/token/user/refresh", methods=["POST"])
def refresh_usuario():
    datos = request.json
    rtoken = datos.get("refresh_token")

    usuario = next((k for k, v in refresh_tokens.items() if v == rtoken), None)
    if not usuario:
        return jsonify({"error": "Refresh token inválido"}), 401

    user = next((u for u in usuarios if u["nombre"] == usuario), None)

    if user["nombre"] in active_user_tokens:
        del active_user_tokens[user["nombre"]]

    payload = {
        "usuario": user["nombre"],
        "rol": user["rol"],
        "scope": "user.read user.write",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }

    access_token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    active_user_tokens[user["nombre"]] = access_token

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 900
    })

@app.route("/token/client/refresh", methods=["POST"])
def refresh_cliente():
    datos = request.json
    rtoken = datos.get("refresh_token")

    cliente = next((k for k, v in refresh_tokens.items() if v == rtoken), None)
    test_data[1] = cliente
    if not cliente:
        return jsonify({"error": "Refresh token inválido"}), 401

    client = None
    for c in clientes:
        if c["client_id"] == cliente:
            client = c
            break

    if cliente in active_client_tokens:
        del active_client_tokens[cliente]


    payload = {
        "client_id": cliente,
        "scope": "service.read service.write",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }

    access_token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    active_client_tokens[cliente] = access_token

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 900
    })

# ------------------------------
# Endpoints protegidos
# ------------------------------
@app.route("/saludo", methods=["GET"])
@token_requerido(["user.read", "service.read"])
def saludo():
    return jsonify({"mensaje": f"Hola {request.usuario.get('usuario', 'microservicio')}!"})

@app.route("/despido", methods=["GET"])
@token_requerido(["user.write", "service.write"])
def despido():
    return jsonify({"mensaje": "Chao, hasta pronto."})

# ------------------------------
# Ejecución
# ------------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000, ssl_context=("cert.pem", "key.pem"))

