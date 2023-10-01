from flask import Flask, request, Response
from google.oauth2 import id_token
from flask_cors import CORS, cross_origin
import google.cloud.logging
import logging
import json
from marshmallow import ValidationError
from google.auth.transport import requests
import schema as ormSchema
from openapi_gen.lib.wrappers import swagger_metadata
from openapi_gen.lib.security import OAuth as SwaggerOAuth
from openapi_gen.swagger import Swagger
from handlers import handle_get, handle_post, handle_put, handle_delete, handle_get_asFeatures

logClient = google.cloud.logging.Client()
logClient.setup_logging()

app = Flask(__name__)
app.config.from_object('config')
app.secret_key = app.config['SECRET_KEY']

cors = CORS(app, resources={
    r"/*": {"origins": "*"},
    # r"/login": {"origins": "*"},
}, supports_credentials=True)

def authorized_user_decorator(func):
    def inner(*args, **kwargs):
        try:
            token = request.headers.get('Authorization').split(" ")[1]
            user = id_token.verify_oauth2_token(token, requests.Request(), app.config['GOOGLE_CLIENT_ID'])
            kwargs["user"]= user
        except Exception as e:
            logging.error("Error: " + str(e))
            return Response(response=json.dumps({'message': 'Unauthorized'}), status=401, mimetype="application/json")
 
        return func(*args, **kwargs)

    inner.__name__ = func.__name__
    return inner

@app.before_request
def basic_authentication():
    if request.method.lower() == 'options':
        return Response()

@app.route("/map-data", methods=['GET'])
@cross_origin(supports_credentials=True)
@authorized_user_decorator
@swagger_metadata(
    summary='Get all map data',
    description='Get all map data',
    query_params=[],
    response_model=[(200, "OK")]
)
def get(*args, **kwargs):
    user = kwargs.get("user")
    return handle_get(user, None)

@app.route("/map-data/features", methods=['GET'])
@cross_origin(supports_credentials=True)
@authorized_user_decorator
@swagger_metadata(
    summary='Get all map data as feature list',
    description='Get all map data as feature list',
    query_params=["bbox"],
    response_model=[(200, "OK")]
)
def getFeatures(*args, **kwargs):
    user = kwargs.get("user")
    bbox = request.args.get('bbox')
    if bbox is None:
        return Response(response=json.dumps({'message': 'bbox geometry is required'}), status=400, mimetype="application/json")
    
    return handle_get_asFeatures(user, bbox)
    
@app.route("/map-data", methods=['POST'])
@cross_origin(supports_credentials=True)
@authorized_user_decorator
@swagger_metadata(
    summary='Create map data',
    description='Create map data',
    query_params=[],
    request_model=ormSchema.BaseSchema.to_dict(),
    response_model=[(200, "OK")]
)
def post(*args, **kwargs):
    user = kwargs.get("user")
    return handle_post(user, request)
    
@app.route("/map-data/<item_id>", methods=['GET'])
@cross_origin(supports_credentials=True)
@authorized_user_decorator
@swagger_metadata(
    summary='Get map data by ID',
    description='Get map data by ID',
    query_params=[],
    request_model=ormSchema.BaseSchema.to_dict(),
    response_model=[(200, "OK")]
)
def get_id(item_id, **kwargs):
    user = kwargs.get("user")
    return handle_get(user, item_id)
    
@app.route("/map-data/<item_id>", methods=['PUT'])
@cross_origin(supports_credentials=True)
@authorized_user_decorator
@swagger_metadata(
    summary='Update map data by ID',
    description='Update map data by ID',
    query_params=[],
    request_model=ormSchema.BaseSchema.to_dict(),
    response_model=[(200, "OK")]
)
def put(item_id, **kwargs):
    user = kwargs.get("user")
    return handle_put(user, request, item_id)
    
@app.route("/map-data/<item_id>", methods=['DELETE'])
@cross_origin(supports_credentials=True)
@authorized_user_decorator
@swagger_metadata(
    summary='Delete map data by ID',
    description='Delete map data by ID',
    query_params=[],
    response_model=[(200, "OK")]
)
def delete(item_id, **kwargs):
    user = kwargs.get("user")
    return handle_delete(item_id, user)
    
swagger = Swagger(
    app=app,
    title='Map Component OL API',
    version='1.0.0',
    description='This is the API for the Map Component OL'
)

swagger = Swagger(
    app=app,
    title='Lookup Codes orchestration API',
    version='1.0.0',
    description='This is the API for the Lookup Codes orchestration layer service',
    auth_schemes=[
        SwaggerOAuth(
            "google", 
            "https://accounts.google.com/o/oauth2/v2/auth", 
            [("scope","openid"), ("email","email"), ("profile","profile")],
            "https://www.googleapis.com/oauth2/v3/certs"
        )
    ],
    servers=["<OL_SERVICE_URL>"],
    produces=["application/json"],
    schemes=["https"]
)

if __name__ == "__main__":
    # Development only: run "python main.py" and open http://localhost:8080
    # When deploying to Cloud Run, a production-grade WSGI HTTP server,
    # such as Gunicorn, will serve the app.
    app.run(host="localhost", port=8080, debug=True)