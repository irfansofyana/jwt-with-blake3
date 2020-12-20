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

    if (is_user_exist(username)):
        return send_response(400, {'message': 'username is already taken!'})

    try:
        curr = mysql.connection.cursor()
        curr.execute("INSERT INTO users VALUES(%s, %s, %s, %s)", (username, generate_password_hash(password), name, email))
        mysql.connection.commit()
        curr.close()

        return send_response(200, {'message': 'user created!'})
    except:
        return send_response(500, {'message': 'error when creating user!'})

@app.route('/login', methods=['POST'])
def signin():
    return request.json

def send_response(statuscode, data):
    resp = {"status": statuscode, "data": data}
    return jsonify(resp), statuscode

def is_user_exist(username):
    try:
        curr = mysql.connection.cursor()
        curr.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = curr.fetchall()
        curr.close()

        if (user is None):
            return False
        else:
            return len(user) > 0
    except Exception as e:
        print(e)

if (__name__=="__main__"):
    app.run(debug=True)