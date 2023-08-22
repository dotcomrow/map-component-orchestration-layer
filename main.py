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
import requests
import schema as ormSchema
from openapi_gen.lib.wrappers import swagger_metadata
from openapi_gen.lib.security import OAuth as SwaggerOAuth
from openapi_gen.swagger import Swagger
from handlers import handle_get, handle_post, handle_put, handle_delete

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

class MyIntrospectTokenValidator(IntrospectTokenValidator):
    def introspect_token(self, token_string):
        try:
            resp_token = google.oauth2.id_token.fetch_id_token(google_requests.Request(), audience)
            user = id_token.verify_oauth2_token(resp_token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID'])
            return user
        except Exception:
            return False
    
    def validate_token(self, token, scopes, request):
        return token
    
require_oauth = ResourceProtector()
require_oauth.register_token_validator(MyIntrospectTokenValidator())

def fetch_user():
    resp_token = google.oauth2.id_token.fetch_id_token(google_requests.Request(), audience)
    user = id_token.verify_oauth2_token(resp_token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID'])
    return user

@app.before_request
def basic_authentication():
    if request.method.lower() == 'options':
        return Response()

@app.route("/map-data", methods=['GET'])
@cross_origin(supports_credentials=True)
@require_oauth()
def get():
    user = fetch_user()
    return handle_get(user, -1)
    
@app.route("/map-data", methods=['POST'])
@cross_origin(supports_credentials=True)
@require_oauth()
def post():
    user = fetch_user()
    return handle_post(user, request)
    
@app.route("/map-data/<item_id>", methods=['GET'])
@cross_origin(supports_credentials=True)
@require_oauth()
def get_id(item_id):
    user = fetch_user()
    return handle_get(user, item_id)
    
@app.route("/map-data/<item_id>", methods=['PUT'])
@cross_origin(supports_credentials=True)
@require_oauth()
def put(item_id):
    user = fetch_user()
    return handle_put(user, request, item_id)
    
@app.route("/map-data/<item_id>", methods=['DELETE'])
@cross_origin(supports_credentials=True)
@require_oauth()
def delete(item_id):
    user = fetch_user()
    return handle_delete(item_id, user)
    
swagger = Swagger(
    app=app,
    title='Map Component OL API',
    version='1.0.0',
    description='This is the API for the Map Component OL'
)

swagger.configure()

if __name__ == "__main__":
    # Development only: run "python main.py" and open http://localhost:8080
    # When deploying to Cloud Run, a production-grade WSGI HTTP server,
    # such as Gunicorn, will serve the app.
    app.run(host="localhost", port=8080, debug=True)