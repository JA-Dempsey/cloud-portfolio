from flask import Flask, request, make_response
from DatastoreDatabase import DatastoreDatabase

app = Flask(__name__)

database = DatastoreDatabase()

api_errors = {}
