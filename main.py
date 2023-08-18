from flask import Flask, request, Response
from authlib.integrations.flask_client import OAuth
from authlib.oauth2.rfc7662 import IntrospectTokenValidator
from authlib.integrations.flask_oauth2 import ResourceProtector
from google.oauth2 import id_token
from google.auth.transport import requests
from flask_cors import CORS, cross_origin
import google.cloud.logging
import logging
import json
from swagger_gen.lib.wrappers import swagger_metadata
from swagger_gen.lib.security import OAuth as SwaggerOAuth
from swagger_gen.swagger import Swagger
from google.oauth2.service_account import Credentials

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
            user = id_token.verify_oauth2_token(resp_token, requests.Request(), app.config['GOOGLE_CLIENT_ID'])
            return user
        except Exception:
            return False
    
    def validate_token(self, token, scopes, request):
        return token
    
require_oauth = ResourceProtector()
require_oauth.register_token_validator(MyIntrospectTokenValidator())

credentials = Credentials.from_service_account_file(
        'google.key',
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    
auth_request = google.auth.transport.requests.Request()
credentials.refresh(auth_request)

@app.before_request
def basic_authentication():
    if request.method.lower() == 'options':
        return Response()

@app.get("/user")
@require_oauth()
@cross_origin()
@swagger_metadata(
    security='google'
)
def addItems():
    googleRequest = google.auth.transport.requests.Request()            
    resp_token = google.oauth2.id_token.fetch_id_token(googleRequest, audience)
    user = id_token.verify_oauth2_token(resp_token,requests.Request(), app.config['GOOGLE_CLIENT_ID'])
    user['token'] = credentials.token
    return Response(response=json.dumps(user), status=201, mimetype="application/json")
    

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