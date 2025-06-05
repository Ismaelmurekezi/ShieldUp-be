from flask import Flask, request, jsonify, make_response
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
import jwt
import datetime
from bson import ObjectId
from bson.json_util import dumps
from functools import wraps
from flask_cors import CORS
from dotenv import load_dotenv, find_dotenv
import os

# Load environment variables from .env file
load_dotenv(find_dotenv())
mongo_db = os.environ.get("MONGODB_URL")
jwt_secret = os.environ.get("JWT_SECRET_KEY")
api_key = os.environ.get("HTTPSMS_API_KEY")
url = os.environ.get("HTTPSMS_URL")
sender = os.environ.get("HTTPSMS_SENDER")
receivers = os.environ.get("HTTPSMS_RECEIVERS")
mongo_db_base = os.environ.get("MONGODB_URL_BASE")



app = Flask(__name__)
CORS(app)
app.config["MONGO_URI"] = mongo_db
app.config["SECRET_KEY"] = jwt_secret

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
users_collection = mongo.db.users
messages_collection = mongo.db.messages

# Helper: Convert MongoDB ObjectId to string
def serialize_user(user):
    return {
        "userId": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "role": user.get("role"),
        "district": user.get("district"),
        "sector": user.get("sector")
    }

# Create a superadmin user if it doesn't exist

def create_superadmin():
    superadmin_email = "superadmin@test.com"
    if not users_collection.find_one({"email": superadmin_email}):
        hashed_pw = bcrypt.generate_password_hash("superpassword").decode("utf-8")
        users_collection.insert_one({
            "username": "SuperAdmin",
            "email": superadmin_email,
            "password": hashed_pw,
            "role": "SuperAdmin",
            "district": "",
            "sector": ""
        })
        print("✅ SuperAdmin created")
    else:
        print("ℹ️ SuperAdmin already exists")

create_superadmin()

# Middleware to protect routes

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get("access_token")
        if not token:
            return jsonify({"message": "Token is missing"}), 401

        try:
            decoded = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            request.user = decoded  # Attach user info to request
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated_function




#  Register route
@app.route('/register', methods=['POST'])
@login_required
def register():
    current_user = request.user
    if current_user.get("role") != "SuperAdmin":
        return jsonify({"message": "Only SuperAdmin can register admins"}), 403

    data = request.get_json()
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")
    district = data.get("district", "")
    sector = data.get("sector", "")
    role = data.get("role", "admin")

    if not email or not username or not password or not sector or not district:
        return jsonify({"message": "Missing required fields"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"message": "User already exists"}), 409

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    user_id = users_collection.insert_one({
        "username": username,
        "email": email,
        "password": hashed_pw,
        "role": role,
        "district": district,
        "sector": sector
    }).inserted_id

    user = users_collection.find_one({"_id": user_id})

    return jsonify({
        "message": f"{role} registered successfully",
        "user": serialize_user(user)
    }), 201




#  Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Missing email or password"}), 400

    user = users_collection.find_one({"email": email})
    if not user or not bcrypt.check_password_hash(user["password"], password):
        return jsonify({"message": "Invalid email or password"}), 401

    token = jwt.encode({
        "user_id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "role": user.get("role"),
        "district": user.get("district"),
        "sector": user.get("sector"),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config["SECRET_KEY"], algorithm="HS256")


    response = make_response(jsonify({
        "message": "Login successful",
        "user": serialize_user(user),
        "token": token
    }))
    response.set_cookie("access_token", token, httponly=True, secure=True, samesite="Lax")
    return response, 200

# UPDATE OWN ACCOUNT ROUTE

@app.route('/users/update', methods=['PUT'])
@login_required
def update_own_account():
    current_user = request.user
    if current_user.get("role") != "admin":
        return jsonify({"message": "You are not authorized"}), 403
    user_email = request.user["email"]
    data = request.get_json()
    
    update_fields = {key: val for key, val in data.items() if key in ["username", "password","email", "district", "sector"]}

    if "password" in update_fields:
        update_fields["password"] = bcrypt.generate_password_hash(update_fields["password"]).decode("utf-8")

    result = users_collection.update_one({"email": user_email}, {"$set": update_fields})
    if result.matched_count == 0:
        return jsonify({"message": "User not found"}), 404

    return jsonify({"message": "Account updated successfully"}), 200


# DELETING ACCOUNT ROUTE
@app.route('/users/<user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    current_user = request.user
    if current_user.get("role") != "SuperAdmin":
        return jsonify({"message": "You are not authorized"}), 403
    
    if not ObjectId.is_valid(user_id):
        return jsonify({"message": "Invalid user ID"}), 400

    user_to_delete = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user_to_delete:
        return jsonify({"message": "User not found"}), 404

    if user_to_delete.get("role") == "SuperAdmin":
        return jsonify({"message": "Cannot delete SuperAdmin"}), 403

    users_collection.delete_one({"_id": ObjectId(user_id)})
    return jsonify({"message": "User deleted successfully"}), 200



#Logout route

@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(jsonify({"message": "Logged out successfully"}))
    
    # Clear the JWT cookie
    response.set_cookie(
        "access_token", "", 
        httponly=True, 
        secure=True, 
        samesite="Lax", 
        expires=0  # Expire immediately
    )
    
    return response, 200



#  Get all messages (for current user)
@app.route('/messages', methods=['GET'])
@login_required
def get_all_messages():
    current_user = request.user
    if current_user.get("role") != "admin":
        return jsonify({"message": "Only Admin can see all messages alert"}), 403
    messages = list(messages_collection.find())
    for m in messages:
        m["_id"] = str(m["_id"])
    return jsonify(messages), 200

# Get a single message
@app.route('/messages/<message_id>', methods=['GET'])
@login_required
def get_message_by_id(message_id):
    current_user = request.user
    if current_user.get("role") != "admin":
        return jsonify({"message": "Only Admin can see this alert message"}), 403
    try:
        message = messages_collection.find_one({"_id": ObjectId(message_id)})
        if not message:
            return jsonify({"message": "Message not found"}), 404
        message["_id"] = str(message["_id"])
        return jsonify(message), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 400
    




# Delete a message
@app.route('/messages/<message_id>', methods=['DELETE'])
@login_required
def delete_message(message_id):
    current_user = request.user
    if current_user.get("role") != "admin":
        return jsonify({"message": "Only admins can delete messages"}), 403

    try:
        result = messages_collection.delete_one({"_id": ObjectId(message_id)})
        if result.deleted_count == 0:
            return jsonify({"message": "Message not found"}), 404
        return jsonify({"message": "Message deleted"}), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 400

    

#  Home or test endpoint
@app.route('/', methods=['GET'])
def home():
    print(api_key, url, sender, receivers,mongo_db_base)
    return jsonify({"message": "Welcome to ShieldUp Auth API"}), 200

if __name__ == '__main__':
    app.run(debug=True)
