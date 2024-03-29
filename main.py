from flask import Flask, request, make_response
from flask import jsonify
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
            ' at least one of the required attributes'},
    '403': {'Error': 'Forbidden'},
    '404': {'Error': 'Not Found'},
    '405': {'Error': 'Method not allowed'},
    '406': {'Error': 'Not acceptable'},
    '415': {'Error': 'Unsupported Media Type'},
}

url = 'https://cs493-portfolio-f.ue.r.appspot.com'
endpoints = {
    'Books': '/books',
    'Libraries': '/libraries',
    'Users': '/users'
}
database = DatastoreDatabase(url, endpoints)


@app.route('/libraries', methods=['POST', 'GET'])
def libraries():

    req_attr = ['name', 'description', 'categories',
                'public', 'owner', 'books']

    if 'Authorization' in request.headers:
        # Verify token/authorization for requests
        payload = verify_jwt(request, False)
        is_user = payload['valid']
    else:
        is_user = False

    if request.method == 'POST':

        # Data from client must be 'application/json'
        is_json = verify_app_json(request)
        if not is_json:
            return make_response(api_errors['406'], 406)

        # Error if user is not a valid user/token
        if not is_user:
            return make_response(api_errors['403'], 403)

        # Get client data and append books info
        data = request.get_json()
        data['books'] = []
        is_valid = verify_attr(data, req_attr)

        # If valid user, add owner info
        if is_user:
            data['owner'] = payload['sub']

        if len(data) != len(req_attr):
            return make_response(api_errors['400'], 400)

        if not is_valid:
            pass

        if len(data) == len(req_attr) and is_valid:
            entity = database.create_single('Libraries', data)
            return make_response(entity, 201)

    if request.method == 'GET':

        # Data from client must be 'application/json'
        is_json = verify_app_json(request)
        if not is_json:
            return make_response(api_errors['406'], 406)

        # User authorization is not required
        # No authorization = public only libraries
        # Authorization = includes private libraries
        # for that user
        if 'Authorization' not in request.headers:
            filters = [('public', '=', True)]
            results = database.get('Libraries', None, filters)
        else:
            filters = [('owner', '=', payload['sub'])]
            results = database.get('Libraries', None, filters)

        # Results will always send the same 200 response
        # With lists of json entities
        return make_response(results, 200)


@app.route('/libraries/<library_id>', methods=['PUT', 'PATCH',
                                               'DELETE', 'GET'])
def libraries_id(library_id):

    req_attr = ['name', 'description', 'categories', 'public']

    if 'Authorization' in request.headers:
        # Verify token/authorization for requests
        payload = verify_jwt(request, False)
        is_user = payload['valid']
    else:
        is_user = False

    if request.method == 'PUT':

        # Data from client must be 'application/json'
        is_json = verify_app_json(request)
        if not is_json:
            return make_response(api_errors['406'], 406)

        # Error if user is not a valid user/token
        if not is_user:
            return make_response(api_errors['403'], 403)

        data = request.get_json()
        is_valid = verify_attr(data, req_attr)

        if len(data) != len(req_attr) or not is_valid:
            return make_response(api_errors['400'], 400)

        if is_valid:
            outcome = database.update_single('Libraries',
                                             int(library_id),
                                             data, payload['sub'])

        if not outcome:
            return make_response(api_errors['404'], 404)
        elif outcome == "403":
            return make_response(api_errors['403'], 403)
        else:
            return make_response(outcome, 200)

    if request.method == 'PATCH':

        # Data from client must be 'application/json'
        is_json = verify_app_json(request)
        if not is_json:
            return make_response(api_errors['406'], 406)

        # Error if user is not a valid user/token
        if not is_user:
            return make_response(api_errors['403'], 403)

        data = request.get_json()
        is_valid = verify_attr(data, req_attr)

        if not is_valid:
            return make_response(api_errors['400'], 400)
        else:
            outcome = database.update_single('Libraries',
                                             int(library_id),
                                             data, payload['sub'])

        if not outcome:
            return make_response(api_errors['404'], 404)
        elif outcome == "403":
            return make_response(api_errors['403'], 403)
        else:
            return make_response(outcome, 200)

    if request.method == 'GET':

        if not is_user:
            return make_response(api_errors['403'], 403)

        results = database.get('Libraries', int(library_id))

        if not results:
            return make_response(api_errors['404'], 404)

        return make_response(results, 200)

    if request.method == 'DELETE':

        library = database.get('Libraries', int(library_id))

        # Clear books from the library before
        # deleting the library
        if library:
            if library['books']:
                book_list = library['books']
                for book in book_list:
                    book['library'] = None
                    database.client.put(book)

        if not is_user:
            return make_response(api_errors['403'], 403)

        # Delete library
        outcome = database.delete_single('Libraries', int(library_id),
                                         payload['sub'])

        if not outcome:
            return make_response(api_errors['404'], 404)
        elif outcome == "403":
            return make_response(api_errors['403'], 403)
        else:
            return make_response("No Content", 204)


@app.route('/libraries/<library_id>/<book_id>', methods=['PUT', 'DELETE'])
def libraries_rel(library_id, book_id):

    if 'Authorization' in request.headers:
        # Verify token/authorization for requests
        payload = verify_jwt(request, False)
        is_user = payload['valid']
    else:
        is_user = False

    if request.method == 'PUT':

        # Error if user is not a valid user/token
        if not is_user:
            return make_response(api_errors['403'], 403)

        library = database._get_entity('Libraries', int(library_id))
        if not library:
            return make_response(api_errors['404'], 404)

        if library['owner'] != payload['sub']:
            return make_response(api_errors['403'], 403)

        book = database._get_entity('Books', int(book_id))
        if not book:
            return make_response(api_errors['404'], 404)

        if book['owner'] != payload['sub']:
            return make_response(api_errors['403'], 403)

        # Change library and put
        book_list = library['books']
        book_list.append(book)
        library['books'] = book_list

        database.client.put(library)

        # Change and put book
        book['library'] = library.key.id
        database.client.put(book)

        return "No Content", 204

    if request.method == 'DELETE':

        # Error if user is not a valid user/token
        if not is_user:
            return make_response(api_errors['403'], 403)

        library = database._get_entity('Libraries', int(library_id))

        if library['owner'] != payload['sub']:
            return make_response(api_errors['403'], 403)

        # Clear individual books from the library
        book_list = library['books']
        new_books = []
        for book in book_list:
            if book.key.id != int(book_id):
                new_books.append(book)

        library['books'] = new_books

        database.client.put(library)

        return "No Content", 204


@app.route('/books', methods=['POST', 'GET'])
def books():

    req_attr = ['name', 'author', 'isbn', 'public', 'owner', 'library']

    if 'Authorization' in request.headers:
        # Verify token/authorization for requests
        payload = verify_jwt(request, False)
        is_user = payload['valid']
    else:
        is_user = False

    if request.method == 'POST':

        # Data from client must be 'application/json'
        is_json = verify_app_json(request)
        if not is_json:
            return make_response(api_errors['406'], 406)

        # Error if user is not a valid user/token
        if not is_user:
            return make_response(api_errors['403'], 403)

        data = request.get_json()
        data['library'] = None  # No default library
        data['owner'] = payload['sub']
        is_valid = verify_attr(data, req_attr)

        if len(data) != len(req_attr) or not is_valid:
            return make_response(api_errors['400'], 400)

        if not is_valid:
            pass

        if len(data) == len(req_attr) and is_valid:
            entity = database.create_single('Books', data)
            return make_response(entity, 201)

    if request.method == 'GET':

        # Data from client must be 'application/json'
        is_json = verify_app_json(request)
        if not is_json:
            return make_response(api_errors['406'], 406)

        # Not authorized, only public returned
        if 'Authorization' not in request.headers:
            filters = [('public', '=', True)]
            results = database.get('Books', None, filters)
        # Authorized, return only users books
        else:
            filters = [('owner', '=', payload['sub'])]
            results = database.get('Books', None, filters)

        return make_response(results, 200)


@app.route('/books/<book_id>', methods=['PUT', 'PATCH', 'DELETE', 'GET'])
def books_id(book_id):

    req_attr = ['name', 'author', 'isbn', 'public']

    if 'Authorization' in request.headers:
        # Verify token/authorization for requests
        payload = verify_jwt(request, False)
        is_user = payload['valid']
    else:
        is_user = False

    if request.method == 'PUT':

        # Data from client must be 'application/json'
        is_json = verify_app_json(request)
        if not is_json:
            return make_response(api_errors['406'], 406)

        # Error if user is not a valid user/token
        if not is_user:
            return make_response(api_errors['403'], 403)

        data = request.get_json()
        is_valid = verify_attr(data, req_attr)

        if len(data) != len(req_attr) or not is_valid:
            return make_response(api_errors['400'], 400)

        if is_valid:
            outcome = database.update_single('Books', int(book_id),
                                             data, payload['sub'])

        if not outcome:
            return make_response(api_errors['404'], 404)
        elif outcome == "403":
            return make_response(api_errors['403'], 403)
        else:
            return make_response(outcome, 200)

    if request.method == 'PATCH':

        # Data from client must be 'application/json'
        is_json = verify_app_json(request)
        if not is_json:
            return make_response(api_errors['406'], 406)

        # Error if user is not a valid user/token
        if not is_user:
            return make_response(api_errors['403'], 403)

        data = request.get_json()
        is_valid = verify_attr(data, req_attr)

        if not is_valid:
            return make_response(api_errors['400'], 400)
        else:
            outcome = database.update_single('Books', int(book_id),
                                             data, payload['sub'])

        if not outcome:
            return make_response(api_errors['404'], 404)
        elif outcome == "403":
            return make_response(api_errors['403'], 403)
        else:
            return make_response(outcome, 200)

    if request.method == 'GET':

        if not is_user:
            return make_response(api_errors['403'], 403)

        results = database.get('Books', int(book_id))
        if not results:
            return make_response(api_errors['404'], 404)

        return make_response(results, 200)

    if request.method == 'DELETE':

        if not is_user:
            return make_response(api_errors['403'], 403)

        # Get book and get library_id
        book = database._get_entity('Books', int(book_id))
        library_id = False
        if book:
            if book['library']:
                library_id = int(book['library'])

        if book:
            if book['owner'] != payload['sub']:
                return make_response(api_errors['403'], 403)

        # If library_id is found, check it for the book
        # entity
        if library_id:
            library = database._get_entity('Libraries', int(library_id))

            # Clear target book from the library
            book_list = library['books']
            new_books = []
            for book in book_list:
                if book.key.id != int(book_id):
                    new_books.append(book)

            # Update the library entity
            library['books'] = new_books
            database.client.put(library)

        outcome = database.delete_single('Books', int(book_id), payload['sub'])

        if not outcome:
            return make_response(api_errors['404'], 404)
        elif outcome == "403":
            make_response(api_errors['403'], 403)
        else:
            return make_response("No Content", 204)


@app.route('/users', methods=['GET'])
def users():
    if request.method == 'GET':

        is_json = verify_app_json(request)
        if not is_json:
            return make_response(api_errors['406'], 406)

        return make_response(database.get('Users', None, None), 200)


# Functions used in endpoints
def verify_attr(data, req_attr):
    for key in data.keys():
        if key not in req_attr:
            return False

    return True


def verify_app_json(request):
    if 'application/json' in request.accept_mimetypes:
        return True
    else:
        return False


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)

    # Update user database entry
    data = {"name": payload['name'],
            "jwt_id": payload['sub']
            }

    filters = [("jwt_id", "=", payload['sub'])]
    user = database.get('Users', None, filters)

    if not user:
        database.create_single('Users', data)

    return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    print(content)
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
