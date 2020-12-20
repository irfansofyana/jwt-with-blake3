import os, json

from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from dotenv import load_dotenv
from BLAKE3 import create_token, verify_token
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()
app = Flask(__name__)

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mysql = MySQL(app)

@app.route('/')
def main():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users")
    rv = cur.fetchall()
    return str(rv)

@app.route('/register', methods=['POST'])
def signup():
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

        return send_response(200, {'user': user})
    except Exception as err:
        print(err)
        return send_response(500, {'message': 'error when login!'})

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

if (__name__=="__main__"):
    app.run(debug=True)