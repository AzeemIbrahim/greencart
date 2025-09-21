from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_cors import CORS
import os
from pymongo import MongoClient

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token
from pymongo import MongoClient
import bcrypt
import os

app = Flask(__name__)
CORS(app)

# Config
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET', 'dev-secret')
jwt = JWTManager(app)

# MongoDB connection
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/greencart')
client = MongoClient(MONGODB_URI)
db = client.get_database()

@app.route("/ping")
def ping():
    return jsonify({"message": "pong"}), 200

# User registration
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Check if user exists
    if db.users.find_one({"username": username}):
        return jsonify({"error": "User already exists"}), 400

    # Hash password
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Insert user
    db.users.insert_one({"username": username, "password": hashed})

    return jsonify({"message": "User registered successfully"}), 201

# User login
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = db.users.find_one({"username": username})
    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        return jsonify({"error": "Invalid username or password"}), 401

    # Create JWT token
    token = create_access_token(identity=username)
    return jsonify({"access_token": token}), 200

if __name__ == "__main__":
    app.run(debug=True)
