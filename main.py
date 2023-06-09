from flask import Flask, request, make_response
from DatastoreDatabase import DatastoreDatabase

app = Flask(__name__)

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

app.route('/users', methods=['POST', 'PUT', 'PATCH', 'DELETE', 'GET'])
def users():

    if request.method == 'POST':
        pass

    if request.method == 'PUT':
        pass

    if request.method == 'PATCH':
        pass

    if request.method == 'DELETE':
        pass

    if request.method == 'GET':
        pass


app.route('/libraries', methods=['POST', 'PUT', 'PATCH', 'DELETE', 'GET'])
def libraries():

    if request.method == 'POST':
        pass

    if request.method == 'PUT':
        pass

    if request.method == 'PATCH':
        pass

    if request.method == 'DELETE':
        pass

    if request.method == 'GET':
        pass


app.route('/books', methods=['POST', 'GET'])
def books():
    if request.method not in methods:

    if request.method == 'POST':
        data = request.get_json()
        if len(data) == 3:
            database.create_single(data)

    if request.method == 'GET':
        pass


app.route('/books/<book_id>', method=['PUT', 'PATCH', 'DELETE'])
def books_id(book_id):

    req_attr = ['name', 'author', 'isbn']

    if request.method == 'PUT':
        data = request.get_json()
        is_valid = verify_attr(data, req_attr)

        if len(data) != len(req_attr):
            return make_response(api_errors['400'], 400)

        if not is_valid:
            pass

        if len(data) == len(req_attr) and is_valid:
            database.update_single('Books', int(book_id), data)

    if request.method == 'PATCH':
        data = request.get_json()
        is_valid = verify_attr(data, req_attr)

        if is_valid:
            outcome = database.update_single(data)

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
