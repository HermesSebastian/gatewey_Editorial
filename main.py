from flask import Flask, jsonify, request
from flask_cors import CORS
from waitress import serve
import datetime
import requests
import json
import logging
from flask_jwt_extended import create_access_token, JWTManager, verify_jwt_in_request, get_jwt_identity
import re  # Asegúrate de importar el módulo 're'

app = Flask(__name__)
CORS(app)

app.config["JWT_SECRET_KEY"] = "super-secret"  # Cambiar por el que sea conveniente
jwt = JWTManager(app)

# Configuración de logs
logging.basicConfig(level=logging.DEBUG)

@app.route("/login", methods=["POST"])
def create_token():
    try:
        data = request.get_json()
        headers = {"Content-Type": "application/json; charset=utf-8"}
        url = dataConfig["url-backend-security"] + '/usuarios/validar'
        response = requests.post(url, json=data, headers=headers)

        if response.status_code == 200:
            user = response.json()
            expires = datetime.timedelta(seconds=60 * 60 * 24)
            access_token = create_access_token(identity=user, expires_delta=expires)
            return jsonify({"token": access_token, "user_id": user["_id"]}), 200
        else:
            logging.error(f"Bad username or password. Status code: {response.status_code}")
            return jsonify({"msg": "Bad username or password"}), 401
    except Exception as e:
        logging.error(f"Error inesperado: {str(e)}")
        print("Error:", e)
        import traceback
        traceback.print_exc()  # Esta línea imprimirá el rastreo de la excepción
        return jsonify({"msg": "Error interno del servidor"}), 500

@app.route("/", methods=["GET"])
def test():
    return jsonify({"mensaje": "Server running..."}), 200

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data

# Decorador antes de la solicitud
@app.before_request
def before_request_callback():
    endPoint = limpiarURL(request.path)
    excludedRoutes = ["/login"]
    if request.path in excludedRoutes:
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"] is not None:
            tienePermiso = validarPermiso(endPoint, request.method, usuario["rol"]["_id"])
            if not tienePermiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401

def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search(r'\d', laParte):  # Corregido: Agregado 'r' antes de la expresión regular
            url = url.replace(laParte, "?")
    return url

def validarPermiso(endPoint, metodo, idRol):
    url = dataConfig["url-backend-security"] + "/permisos-roles/validar-permiso/rol/" + str(idRol)
    tienePermiso = False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {
        "url": endPoint,
        "metodo": metodo
    }
    response = requests.get(url, json=body, headers=headers)
    try:
        data = response.json()
        if "_id" in data:
            tienePermiso = True
    except:
        pass
    return tienePermiso
################################Redireccionamiento Autor###########################################
@app.route("/autor", methods=['GET'])
def getAutores():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/autor'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/autor", methods=['POST'])
def crearAutor():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/autor'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/autor/<string:id>", methods=['GET'])
def getAutor(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/autor/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/autor/<string:id>", methods=['PUT'])
def modificarAutor(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/autor/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/autor/<string:id>", methods=['DELETE'])
def eliminarAutor(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/autor/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
################################Redireccionamiento publicacion###########################################
@app.route("/publicacion", methods=['GET'])
def getPublicacionById():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/publicacion'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/publicacion", methods=['POST'])
def crearPublicacion():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/publicacion'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/publicacion/<string:id>", methods=['GET'])
def getPublicacion(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/publicacion/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/publicacion/<string:id>", methods=['PUT'])
def modificarPublicacion(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/publicacion/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/publicacion/<string:id>", methods=['DELETE'])
def eliminarPublicacion(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/publicacion/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
################################Redireccionamiento Autor Publicacion###########################################
@app.route("/autorpublicacion", methods=['GET'])
def getAutorPublicacionById():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/autorpublicacion'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/autorpublicacion/autor/<string:id_autor>/publicacion/<string:id_publicacion>", methods=['POST'])
def crearAutorPublicacion(id_autor ,id_publicacion):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/autorpublicacion/autor/'+ id_autor+'/publicacion/'+id_publicacion
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/autorpublicacion/<string:id>", methods=['GET'])
def getAutorPublicacion(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/autorpublicacion/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/autorpublicacion/<string:id_autorpublicacion>/autor/<string:id_autor>/publicacion/<string:id_publicacion>", methods=['PUT'])
def modificarAutorPublicacion(id_autorpublicacion, id_autor, id_publicacion):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/autorpublicacion/'+id_autorpublicacion+'/autor/'+ id_autor+'/publicacion/'+id_publicacion
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/autorpublicacion/<string:id>", methods=['DELETE'])
def eliminarAutorPublicacion(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/autorpublicacion/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
################################Redireccionamiento Tipo publicacion###########################################
@app.route("/tipopublicacion", methods=['GET'])
def getTipoPublicacionById():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/tipopublicacion'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/tipopublicacion", methods=['POST'])
def crearTipoPublicacion():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/tipopublicacion'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/tipopublicacion/<string:id>", methods=['GET'])
def getTipoPublicacion(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/tipopublicacion/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/tipopublicacion/<string:id>", methods=['PUT'])
def modificarTipoPublicacion(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/tipopublicacion/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/tipopublicacion/<string:id>", methods=['DELETE'])
def eliminarTipoPublicacion(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-fup"] + '/tipopublicacion/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)
################################################################################################

if __name__ == "__main__":
    dataConfig = loadFileConfig()
    logging.info(f"Server running: http://{dataConfig['url-backend']}:{dataConfig['port']}")
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])
