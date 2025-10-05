from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

# ------------------------------
# Middleware simulado para JWT
# ------------------------------
def check_jwt(roles_permitidos):
    """
    Valida un token simulado y verifica el rol permitido.
    roles_permitidos: lista de roles que pueden acceder al endpoint.
    """
    def wrapper(func):
        @wraps(func)  # Mantiene el nombre original de la función
        def inner(*args, **kwargs):
            token = request.headers.get("Authorization")
            if not token:
                return jsonify({
                    "status": 401,
                    "error": "Token inválido o faltante"
                }), 401

            # Simulación de roles
            if token == "admin-token":
                rol = "admin"
            elif token == "basico-token":
                rol = "basico"
            else:
                return jsonify({
                    "status": 401,
                    "error": "Token inválido"
                }), 401

            # Verifica permisos
            if rol not in roles_permitidos:
                return jsonify({
                    "status": 403,
                    "error": "Acceso denegado: se requiere rol adecuado"
                }), 403

            return func(*args, **kwargs)
        return inner
    return wrapper

# ------------------------------
# Endpoints
# ------------------------------
@app.route("/")
def home():
    return jsonify({
        "status": 200,
        "message": "API funcionando correctamente"
    }), 200

@app.route("/saludo")
@check_jwt(["basico", "admin"])
def saludo():
    return jsonify({
        "status": 200,
        "message": "Acceso permitido a /saludo"
    }), 200

@app.route("/despido")
@check_jwt(["admin"])
def despido():
    return jsonify({
        "status": 200,
        "message": "Acceso permitido a /despido solo para admin"
    }), 200

# ------------------------------
# Ejecutar servidor
# ------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True, ssl_context=("cert.pem", "key.pem"))

