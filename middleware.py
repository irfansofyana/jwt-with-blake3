from werkzeug.wrappers import Request, Response, ResponseStream
from jwt_blake3 import verify_token, extract_header_payload
import json
import os

class middleware():
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        request = Request(environ)
        paths = request.path.split('/')
        
        protected_base_uri = ['users']

        if (paths[1] in protected_base_uri):
            if ('HTTP_AUTHORIZATION' not in environ):
                resp = {"status": 401, "data": {'message': 'Unauthorized'}}
                res = Response(json.dumps(resp), mimetype= 'application/json', status=401)
                return res(environ, start_response)

        auth_headers = request.headers['Authorization'].split(' ')
        if (len(auth_headers) != 2):
            resp = {"status": 401, "data": {'message': 'Authorization key is not Bearer Token type!'}}
            res = Response(json.dumps(resp), mimetype= 'application/json', status=401)
            return res(environ, start_response)

        jwt_token = auth_headers[1]
        if (verify_token(jwt_token, os.getenv('SECRET_KEY'))):
            [header, payload] = extract_header_payload(jwt_token)
            environ['user'] = payload
            return self.app(environ, start_response)
        
        resp = {"status": 401, "data": {'message': 'Token is not verified!'}}
        res = Response(json.dumps(resp), mimetype= 'application/json', status=401)
        return res(environ, start_response)