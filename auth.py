import urllib2

import google.auth.transport.requests
import google.oauth2.id_token
from google.oauth2.service_account import Credentials
import config

credentials = Credentials.from_service_account_file(
        'google.key',
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    
auth_request = google.auth.transport.requests.Request()
credentials.refresh(auth_request)

def make_authorized_get_request(endpoint, data, method):
    """
    make_authorized_get_request makes a GET request to the specified HTTP endpoint
    by authenticating with the ID token obtained from the google-auth client library
    using the specified audience value.
    """

    # Cloud Run uses your service's hostname as the `audience` value
    # audience = 'https://my-cloud-run-service.run.app/'
    # For Cloud Run, `endpoint` is the URL (hostname + path) receiving the request
    # endpoint = 'https://my-cloud-run-service.run.app/my/awesome/url'

    req = urllib2.Request(endpoint, data, method)

    auth_req = google.auth.transport.requests.Request()
    id_token = google.oauth2.id_token.fetch_id_token(auth_req, config.AUDIENCE)

    req.add_header("Authorization", f"Bearer {id_token}")
    response = urllib2.urlopen(req)

    return response.read()