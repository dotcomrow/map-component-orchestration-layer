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

@app.before_request
def basic_authentication():
    if request.method.lower() == 'options':
        return Response()
    
@app.route("/map-data/<item_id>", methods=['GET', 'PUT', 'DELETE'])
@require_oauth()
@cross_origin()
def handle_request(item_id):
    resp_token = google.oauth2.id_token.fetch_id_token(google_requests.Request(), audience)
    user = id_token.verify_oauth2_token(resp_token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID'])
    logging.info("item id {}".format(item_id))
    if item_id.isdigit() == False:
        return Response(response=json.dumps({'message': 'Invalid item id'}), status=400, mimetype="application/json")
    item_id = int(item_id)
    match (request.method):
        case 'GET':
            return handle_get(user, item_id)
        case 'PUT':
            return handle_put(user, request, item_id)    
        case 'DELETE':
            return handle_delete(item_id, user)
        case _:
            return Response(response=json.dumps({'message': 'Method not allowed'}), status=405, mimetype="application/json")

@app.route("/map-data", methods=['GET', 'POST'])
@require_oauth()
@cross_origin()
def handle_request_no_id():
    resp_token = google.oauth2.id_token.fetch_id_token(google_requests.Request(), audience)
    user = id_token.verify_oauth2_token(resp_token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID'])
    
    match (request.method):
        case 'GET':
            return handle_get(user, -1)
        case 'POST':
            return handle_post(user, request)
        case _:
            return Response(response=json.dumps({'message': 'Method not allowed'}), status=405, mimetype="application/json")
    
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