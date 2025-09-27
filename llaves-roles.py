# instalar dependencias: pip install flask pyjwt cryptography

from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

# Llaves RSA (válidas)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzL3mVevbo7bYlx3cWXYVYhH8BRaRUg1qE3stCpLBVtwjYZpX
a/6SvdaEojAhbp8UtQ4Tb3IN75tPvXxg8mqNEvHhtSWWU++IEVAKlKvV4b4Xm2ge
XNoXrxkG23Ud1dMJlqEyqSpV0pvhikAc0HpvMrj4cBPcz+1hrSkTu+xNvJmGuGEb
JSx5lM7l95t5ab66f9aUwSyeb/PCOSrh4ZnUGsbEJb1sxNvBWqupw3PgLP2PztYY
FJhHrs8Lx6RaqYZh7hyRhOQp2QJHzqJG78CnEsD9nd1tTpgKJo4MslAZxW/qM9Xk
FSos7q/LDEbAPKN3rAcIZMtjfaT9uT3KacQbRwIDAQABAoIBABhxvF0MyzCIGx4N
D/qQ3lUDFsdnK4r69HyHiB7FkAYKxNVXMMjWb9cHf8C3HwK0+8tMpsyr1kTQ4oiT
LVdD7LGkzAId8CeFstWwnU8bONMD9kjQ4+ROjP0yH1CMUoX/qQou7Aa6cK/21jcl
kMvNf0nL3Um5oHZloDK1GR45ZjYZTZddXwoOd4XgYqkC0OfY24Rud4pFQjZ4XxjS
dBMiDLFciReh2tHvhZftI4WjIV6y9uD7tAzqPL7H8SmUMDpuUtMUMJcSZ+adVa59
OHbA9TtALkCkbHYALl8Fnh1fhPaSNeRJ6mgU1m/dKfMKDRoyAVPBIplEk7cT6K1k
+kgcCgECgYEA9U5CP2FOSc/JRJSKvWswFfViLRqQkq1kZZmsW1x8Qq/1vYfZgOtS
m13hW5sOW4oH2ioAo2roQjvO2oZJh8fFv8y4l2lw1hROTxckym/yfNZpS0I31wXU
pcektODDG17ZiyWBVZhrqLKrFf3Zk9Q90nD7hCnnMbdzE9A1M6lSxK0CgYEA1+YZ
p2rcLqBoP9iJOCaNvVkbChEuDZYFpcavll10iVhrRY9kwbB/HRTWQFdtdwozn/cf
OjNU88x/RGu6VDWj0JqzKqV+zpuP4i7YcQzFnDdyv+CHCvDQoH3tew0cF29Q4fVs
aFj82r6sY5UikFjSMCCe8U4k9h/kcMEkVwYlEvMCgYAqXlCaeI6Jg0eFtHeYimPo
qIT94X9mpLPG1kMF30t4x7lmS85Pab0+30BzO0XW+nKN2rN/jaxkkN7+v3H7Zc5y
P/0uXuw4OlIf6nQtV0arjFnfVqQ1XcGlUhsPDlI1ojIbCgsyXNfrbhlffLUKDN9u
1S7wI6O8zUsZ6loYbqLuwQKBgFeQWx99T2aYcf/Pr0pCd2jIUIoXCdIM1ZpHmsrZ
2JZ+L8EGHtIfLoODdlBMm+9Lf3kiclu06lX/YO2j14V9+ab+Ka1HxGFsFqk9LVQo
MtwbUb3Q4MfM2Lz1bMkQ0B8FV/kWxFoA1o+6HLQsm3cOx7rjStcgVv3vTi+GbmZa
b09hAoGBAJx5OybNTN8PgV7PYPsP+EZSPYjAW4HqDUYe7h6ZRP1JEMXEvibAIFCN
jRcpDeoP+d+AlHvsRLVOuV3a+7xqniPkeMbdUwHrbfSbb3fAqQz5DMMOswfxiHgU
0zq59YMLZn1Wjvli9Q4Y+TrpLxq9O5pKInl1TxN0InbD7i3YlNfN
-----END RSA PRIVATE KEY-----"""

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzL3mVevbo7bYlx3cWXYV
YhH8BRaRUg1qE3stCpLBVtwjYZpXa/6SvdaEojAhbp8UtQ4Tb3IN75tPvXxg8mqN
EvHhtSWWU++IEVAKlKvV4b4Xm2geXNoXrxkG23Ud1dMJlqEyqSpV0pvhikAc0Hpv
Mrj4cBPcz+1hrSkTu+xNvJmGuGEbJSx5lM7l95t5ab66f9aUwSyeb/PCOSrh4ZnU
GsbEJb1sxNvBWqupw3PgLP2PztYYFJhHrs8Lx6RaqYZh7hyRhOQp2QJHzqJG78Cn
EsD9nd1tTpgKJo4MslAZxW/qM9XkFSos7q/LDEbAPKN3rAcIZMtjfaT9uT3KacQb
RwIDAQAB
-----END PUBLIC KEY-----"""

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



