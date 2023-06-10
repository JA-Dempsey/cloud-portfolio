from flask import Flask, request, make_response, redirect
from flask import _request_ctx_stack, jsonify, render_template
from flask import session, url_for
from DatastoreDatabase import DatastoreDatabase
import requests

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt

from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode


app = Flask(__name__)

CLIENT_ID = '1H69CneNNBw5Ods5MnteZWSalQEigrbi'
CLIENT_SECRET = 'b_cHtop9qWOBmovWjZ86AB0Ml_h7NRE4iSaSN2yrGgATJdcrTuvaAVWdb1WA5W2U'
DOMAIN = 'cs493-dempsjam-portfolio.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


# This code is adapted from https://auth0.com/docs/quickstart/backend/python/
# 01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request, auto_return=True):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        if auto_return:
            raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        if auto_return:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)

    if unverified_header["alg"] == "HS256":
        if auto_return:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)

    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            if auto_return:
                raise AuthError({"code": "token_expired",
                                "description": "token is expired"}, 401)
            else:
                payload['valid'] = False
        except jwt.JWTClaimsError:
            if auto_return:
                raise AuthError({"code": "invalid_claims",
                                "description":
                                    "incorrect claims,"
                                    " please check the audience and issuer"},
                                401)
            else:
                payload['valid'] = False
        except Exception:
            if auto_return:
                raise AuthError({"code": "invalid_header",
                                "description":
                                    "Unable to parse authentication"
                                    " token."}, 401)
            else:
                payload['valid'] = False

        payload['valid'] = True
        return payload
    else:
        if auto_return:
            raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
        else:
            payload['valid'] = False
            return payload


api_errors = {
    '400': {'Error': 'The request object is missing'
            'at least one of the required attributes'},
    '403': {'Forbidden'},
    '404': {'Not Found'},
    '405': {'Method not allowed'},
    '406': {'Not acceptable'},
    '415': {'Unsupported Media Type'},
}

url = '127.0.0.1'
database = DatastoreDatabase(url)


@app.route('/libraries', methods=['POST', 'GET'])
def libraries():

    req_attr = ['name', 'description', 'categories', 'owner', 'public']

    if request.method == 'POST':
        data = request.get_json()
        data['books'] = []
        is_valid = verify_attr(data, req_attr)

        if len(data) != len(req_attr):
            return make_response(api_errors['400'], 400)

        if not is_valid:
            pass

        if len(data) == len(req_attr) and is_valid:
            database.create_single('Libraries', data)

    if request.method == 'GET':
        if 'Authorization' not in request.headers:
            filters = [('public', '=', True)]
            results = database.get('Libraries', None, filters)

            return make_response(results, 200)

        else:
            payload = verify_jwt(request)
            filters = [('owner', '=', payload['sub'])]
            results = database.get('Libraries', None, filters)


@app.route('/libraries/<library_id>', methods=['PUT', 'PATCH', 'DELETE'])
def libraries_id(library_id):

    req_attr = ['name', 'description', 'categories', 'owner', 'public']

    if request.method == 'PUT':
        data = request.get_json()
        is_valid = verify_attr(data, req_attr)

        if len(data) != len(req_attr):
            return make_response(api_errors['400'], 400)

        if is_valid:
            outcome = database.update_single('Libraries',
                                             int(library_id), data)

        if not outcome:
            return make_response(api_errors['404'], 404)
        else:
            return make_response("No Content", 204)

    if request.method == 'PATCH':
        data = request.get_json()
        is_valid = verify_attr(data, req_attr)

        if is_valid:
            outcome = database.update_single('Libraries',
                                             int(library_id), data)

        if not outcome:
            return make_response(api_errors['404'], 404)
        else:
            return make_response("No Cotent", 204)

    if request.method == 'DELETE':
        outcome = database.delete_single('Libraries', int(library_id))

        if not outcome:
            return make_response(api_errors['404'], 404)
        else:
            return make_response("No Content", 204)


@app.route('libraries/<library_id>/<book_id>', methods=['PUT', 'DELETE'])
def libraries_rel():
    if request.method == 'PUT':
        pass

    if request.method == 'DELETE':
        pass


@app.route('/books', methods=['POST', 'GET'])
def books():

    req_attr = ['name', 'author', 'isbn', 'public', 'owner']

    if request.method == 'POST':
        data = request.get_json()
        data['library'] = None  # No default library
        is_valid = verify_attr(data, req_attr)

        if len(data) != len(req_attr):
            return make_response(api_errors['400'], 400)

        if not is_valid:
            pass

        if len(data) == len(req_attr) and is_valid:
            database.create_single('Books', data)

    if request.method == 'GET':
        # Not authorized, only public returned
        if 'Authorization' not in request.headers:
            filters = [('public', '=', True)]
            results = database.get('Books', None, filters)

            return make_response(results, 200)

        # Authorized, return only users books
        else:
            payload = verify_jwt(request)
            filters = [('owner', '=', payload['sub'])]
            results = database.get('Books', None, filters)


@app.route('/books/<book_id>', method=['PUT', 'PATCH', 'DELETE'])
def books_id(book_id):

    req_attr = ['name', 'author', 'isbn', 'owner']

    if request.method == 'PUT':
        data = request.get_json()
        is_valid = verify_attr(data, req_attr)

        if len(data) != len(req_attr):
            return make_response(api_errors['400'], 400)

        if is_valid:
            outcome = database.update_single('Books', int(book_id), data)

        if not outcome:
            return make_response(api_errors['404'], 404)
        else:
            return make_response("No Content", 204)

    if request.method == 'PATCH':
        data = request.get_json()
        is_valid = verify_attr(data, req_attr)

        if is_valid:
            outcome = database.update_single('Books', int(book_id), data)

        if not outcome:
            return make_response(api_errors['404'], 404)
        else:
            return make_response("No Content", 204)

    if request.method == 'DELETE':
        outcome = database.delete_single('Books', int(book_id))

        if not outcome:
            return make_response(api_errors['404'], 404)
        else:
            return make_response("No Content", 204)


# Functions used in endpoints
def verify_attr(data, req_attr):
    for key in data.keys():
        if key not in req_attr:
            return False

    return True


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password',
            'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }

    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type': 'application/json'}


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True, ssl_context='adhoc')
