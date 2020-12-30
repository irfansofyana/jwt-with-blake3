import os
import json

from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from dotenv import load_dotenv
from jwt_blake3 import create_token, verify_token
from werkzeug.security import generate_password_hash, check_password_hash
from middleware import middleware

load_dotenv()
app = Flask(__name__)
app.wsgi_app = middleware(app.wsgi_app)

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mysql = MySQL(app)


@app.route('/register', methods=['POST'])
def register():
    username = request.json['username']
    password = request.json['password']
    name = request.json['name']
    email = request.json['email']

    user = find_user(username)
    if (user is not None and len(user) > 0):
        return send_response(400, {'message': 'username is already taken!'})

    try:
        curr = mysql.connection.cursor()
        curr.execute(
            "INSERT INTO users VALUES(%s, %s, %s, %s)",
            (username, generate_password_hash(password), name, email)
        )
        mysql.connection.commit()
        curr.close()

        return send_response(200, {'message': 'user created!'})
    except Exception as err:
        print(err)
        return send_response(500, {'message': 'error when creating user!'})


@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']

    try:
        user = find_user(username)

        if (user is None or len(user) == 0):
            return send_response(404, {'message': 'user not found!'})

        hashed_password = user[0][1]

        if not(check_password_hash(hashed_password, password)):
            return send_response(401, {'message': 'username or password is incorrect!'})

        data = json.dumps({'username': user[0][0]})
        jwt_token = create_token(payload=data, secret=os.getenv('SECRET_KEY'))
        return send_response(200, {'jwt_token': jwt_token})
    except Exception as err:
        print(err)
        return send_response(500, {'message': 'error when login!'})


@app.route('/users/<username>', methods=['GET'])
def get_specific_user(username):
    try:
        curr = mysql.connection.cursor()
        curr.execute(
            'SELECT username, name, email FROM users WHERE username = %s', (username,))
        user = curr.fetchall()
        curr.close()

        if (user is None or len(user) == 0):
            return send_response(404, {'message': 'user not found!'})
        else:
            return send_response(200, {
                'username': user[0][0],
                'name': user[0][1],
                'email': user[0][2]
            })
    except Exception as err:
        print(err)
        return send_response(500, {'message': 'error when GET detail of a user'})


@app.route('/users/<username>', methods=['PUT'])
def update_specific_user(username):
    try:
        user = json.loads(request.environ['user'])
        if (user['username'] != username):
            return send_response(403, {'message': 'you are not allowed to modify other user!'})

        new_name = request.json['name']
        new_email = request.json['email']
        new_password = request.json['email']

        curr = mysql.connection.cursor()
        curr.execute(
            'UPDATE users SET name = %s, email = %s, password = %s WHERE username = %s',
            (new_name, new_email, generate_password_hash(new_password), username)
        )
        mysql.connection.commit()
        curr.close()

        return send_response(200, {'message': 'user information is successfully updated!'})
    except Exception as err:
        print(err)
        return send_response(500, {'message': 'error when update a user'})


def send_response(statuscode, data):
    resp = {"status": statuscode, "data": data}
    return jsonify(resp), statuscode


def find_user(username):
    try:
        curr = mysql.connection.cursor()
        curr.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = curr.fetchall()
        curr.close()

        return user
    except Exception as err:
        print(err)
        return send_response(500, {'message': 'error when find user by username!'})


if (__name__ == "__main__"):
    app.run(debug=True)
