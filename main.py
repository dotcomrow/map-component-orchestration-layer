from flask import Flask, request, Response
from authlib.integrations.flask_client import OAuth
from authlib.oauth2.rfc7662 import IntrospectTokenValidator
from authlib.integrations.flask_oauth2 import ResourceProtector
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from flask_cors import CORS, cross_origin
import google.cloud.logging
import logging
import json
from marshmallow import ValidationError
from swagger_gen.lib.wrappers import swagger_metadata
from swagger_gen.lib.security import OAuth as SwaggerOAuth
from swagger_gen.swagger import Swagger
import requests
import schema as ormSchema

logClient = google.cloud.logging.Client()
logClient.setup_logging()

app = Flask(__name__)
app.config.from_object('config')
app.secret_key = app.config['SECRET_KEY']
audience = app.config['AUDIENCE']

cors = CORS(app, resources={
    r"/*": {"origins": "*"},
    # r"/login": {"origins": "*"},
}, supports_credentials=True)
oauth = OAuth(app)
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

class MyIntrospectTokenValidator(IntrospectTokenValidator):
    table_built = False
    delete_table_built = False
    def introspect_token(self, token_string):
        try:
            request = google.auth.transport.requests.Request()            
            resp_token = google.oauth2.id_token.fetch_id_token(request, audience)
            user = id_token.verify_oauth2_token(resp_token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID'])
            return user
        except Exception:
            return False
    
    def validate_token(self, token, scopes, request):
        return token
    
require_oauth = ResourceProtector()
require_oauth.register_token_validator(MyIntrospectTokenValidator())

METADATA_HEADERS = {'Metadata-Flavor': 'Google'}
METADATA_URL = 'http://metadata.google.internal/computeMetadata/v1/' \
                           'instance/service-accounts/default/identity?' \
                           'audience={}'

def fetch_identity_token(audience):
    # Construct a URL with the audience and format.
    url = METADATA_URL.format(audience)

    # Request a token from the metadata server.
    r = requests.get(url, headers=METADATA_HEADERS)

    r.raise_for_status()
    return r.text

def ProcessPayload(url, method, payload):
    id_token = fetch_identity_token(url)
    
    headers        = {
        'Authorization': f'Bearer {id_token}',
        'Content-Type': 'application/json'}
    response       = requests.request(method, url, json=payload, headers=headers)
    return response

@app.before_request
def basic_authentication():
    if request.method.lower() == 'options':
        return Response()

@app.get("/map-data")
@require_oauth()
@cross_origin()
@swagger_metadata(
    security='google'
)
def getData():
    googleRequest = google.auth.transport.requests.Request()            
    resp_token = google.oauth2.id_token.fetch_id_token(googleRequest, audience)
    user = id_token.verify_oauth2_token(resp_token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID']) 
    result = ProcessPayload(app.config['DATA_LAYER_URL'] + user['sub'], 'GET', None)
    return Response(response=json.dumps(result.json()), status=200, mimetype="application/json")

@app.post("/map-data")
@require_oauth()
@cross_origin()
@swagger_metadata(
    security='google'
)
def saveData():
    googleRequest = google.auth.transport.requests.Request()            
    resp_token = google.oauth2.id_token.fetch_id_token(googleRequest, audience)
    user = id_token.verify_oauth2_token(resp_token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID'])
    request_data = request.get_json()
    
    if request_data is None:
        return Response(response=json.dumps({'message': 'No data provided'}), status=400, mimetype="application/json")
    
    schema = ormSchema.BaseSchema()
    try:
        # Validate request body against schema data types
        result = schema.load(request_data)
    except ValidationError as err:
        logging.error(err.messages)
        return Response(response=json.dumps({'message': 'Invalid data provided'}), status=400, mimetype="application/json")
    
    result = ProcessPayload(app.config['DATA_LAYER_URL'] + user['sub'], 'POST', request_data)
    return Response(response=json.dumps(result.json()), status=200, mimetype="application/json") 

@app.delete("/map-data/<path:item_id>")
@require_oauth()
@cross_origin()
@swagger_metadata(
    security='google'
)
def deleteData(item_id):
    googleRequest = google.auth.transport.requests.Request()            
    resp_token = google.oauth2.id_token.fetch_id_token(googleRequest, audience)
    user = id_token.verify_oauth2_token(resp_token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID'])
     
    if item_id is None:
        return Response(response=json.dumps({'message': 'Item ID is required'}), status=400, mimetype="application/json")
    
    result = ProcessPayload(app.config['DATA_LAYER_URL'] + user['sub'] + "/" + item_id, 'DELETE', None)
    if result.status_code == 200:
        return Response(response=json.dumps({'message': 'Item deleted'}), status=200, mimetype="application/json")
    elif result.status_code == 404:
        return Response(response=json.dumps({'message': 'Item not found'}), status=200, mimetype="application/json")
    else:
        return Response(response=json.dumps({'message': 'Error deleting item'}), status=500, mimetype="application/json")

swagger = Swagger(
    app=app,
    title='Test API',
    auth_schemes=[SwaggerOAuth(
        name='google',
        auth_url='https://accounts.google.com/o/oauth2/v2/auth',
        scopes=[('openid', 'openid'), ('email', 'email'), ('profile', 'profile')]
    )]
)

swagger.configure()

if __name__ == "__main__":
    # Development only: run "python main.py" and open http://localhost:8080
    # When deploying to Cloud Run, a production-grade WSGI HTTP server,
    # such as Gunicorn, will serve the app.
    app.run(host="localhost", port=8080, debug=True)