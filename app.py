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
import pymongo

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
CORS(app, supports_credentials=True)
app.config["MONGO_URI"] = mongo_db
app.config["SECRET_KEY"] = jwt_secret

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
users_collection = mongo.db.users
messages_collection = mongo.db.messages

# Helper: Convert MongoDB ObjectId to string and format timestamps
def serialize_user(user):
    return {
        "userId": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "role": user.get("role"),
        "district": user.get("district"),
        "sector": user.get("sector"),
        "createdAt": user.get("createdAt"),
        "updatedAt": user.get("updatedAt")
    }

# Create a superadmin user if it doesn't exist
def create_superadmin():
    superadmin_email = "superadmin@test.com"
    if not users_collection.find_one({"email": superadmin_email}):
        hashed_pw = bcrypt.generate_password_hash("superpassword").decode("utf-8")
        current_time = datetime.datetime.utcnow()
        users_collection.insert_one({
            "username": "SuperAdmin",
            "email": superadmin_email,
            "password": hashed_pw,
            "role": "SuperAdmin",
            "district": "",
            "sector": "",
            "createdAt": current_time,
            "updatedAt": current_time
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

# Register route
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
    current_time = datetime.datetime.utcnow()
    
    user_id = users_collection.insert_one({
        "username": username,
        "email": email,
        "password": hashed_pw,
        "role": role,
        "district": district,
        "sector": sector,
        "createdAt": current_time,
        "updatedAt": current_time
    }).inserted_id

    user = users_collection.find_one({"_id": user_id})

    return jsonify({
        "message": f"{role} registered successfully",
        "user": serialize_user(user)
    }), 201

# Login route
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

    # Update lastLoginAt timestamp
    users_collection.update_one(
        {"_id": user["_id"]}, 
        {"$set": {"lastLoginAt": datetime.datetime.utcnow()}}
    )

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

# GET ALL USERS ROUTE
@app.route('/users', methods=['GET'])
@login_required
def get_all_users():
    current_user = request.user
    if current_user.get("role") != "SuperAdmin":
        return jsonify({"message": "Only SuperAdmin can view all users"}), 403

    users = list(users_collection.find({}, {"password": 0}))  # exclude passwords
    for user in users:
        user["_id"] = str(user["_id"])
    return jsonify(users), 200

# GET SINGLE USER ROUTE
@app.route('/users/<user_id>', methods=['GET'])
@login_required
def get_user_by_id(user_id):
    current_user = request.user
    if current_user.get("role") != "SuperAdmin":
        return jsonify({"message": "Only SuperAdmin can view user details"}), 403

    if not ObjectId.is_valid(user_id):
        return jsonify({"message": "Invalid user ID"}), 400

    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"password": 0})  # exclude password
    if not user:
        return jsonify({"message": "User not found"}), 404

    user["_id"] = str(user["_id"])
    return jsonify(user), 200

# UPDATE OWN ACCOUNT ROUTE
@app.route('/users/update', methods=['PUT'])
@login_required
def update_own_account():
    current_user = request.user
    if current_user.get("role") != "admin":
        return jsonify({"message": "You are not authorized"}), 403
    
    user_email = request.user["email"]
    data = request.get_json()
    
    update_fields = {key: val for key, val in data.items() if key in ["username", "password", "email", "district", "sector"]}

    if "password" in update_fields:
        update_fields["password"] = bcrypt.generate_password_hash(update_fields["password"]).decode("utf-8")

    # Always update the updatedAt timestamp
    update_fields["updatedAt"] = datetime.datetime.utcnow()

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

# Logout route
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

# Get all messages with pagination
@app.route('/messages', methods=['GET'])
@login_required
def get_all_messages():
    current_user = request.user
    if current_user.get("role") != "admin":
        return jsonify({"message": "Only Admin can see all messages alert"}), 403
    
    try:
        # Get pagination parameters
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        
        # Calculate skip value
        skip = (page - 1) * limit
        
        # Get total count
        total_messages = messages_collection.count_documents({})
        
        # Get paginated messages, sorted by timestamp (newest first)
        messages = list(messages_collection.find()
                       .sort("timestamp", pymongo.DESCENDING)
                       .skip(skip)
                       .limit(limit))
        
        # Convert ObjectId to string
        for message in messages:
            message["_id"] = str(message["_id"])
        
        # Calculate pagination info
        total_pages = (total_messages + limit - 1) // limit
        
        pagination_info = {
            "currentPage": page,
            "totalPages": total_pages,
            "totalMessages": total_messages,
            "limit": limit,
            "hasNext": page < total_pages,
            "hasPrev": page > 1
        }
        
        return jsonify({
            "messages": messages,
            "pagination": pagination_info
        }), 200
        
    except Exception as e:
        return jsonify({"message": f"Error fetching messages: {str(e)}"}), 500

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

# Update message status
@app.route('/messages/<message_id>/status', methods=['PUT'])
@login_required
def update_message_status(message_id):
    current_user = request.user
    if current_user.get("role") != "admin":
        return jsonify({"message": "Only admins can update message status"}), 403

    try:
        data = request.get_json()
        new_status = data.get("status")
        
        if not new_status:
            return jsonify({"message": "Status is required"}), 400
        
        if new_status not in ["unread", "acknowledged"]:
            return jsonify({"message": "Invalid status. Must be 'unread' or 'acknowledged'"}), 400
        
        update_data = {"status": new_status}
        if new_status == "acknowledged":
            update_data["acknowledged_at"] = datetime.datetime.utcnow()
        
        result = messages_collection.update_one(
            {"_id": ObjectId(message_id)}, 
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            return jsonify({"message": "Message not found"}), 404
            
        return jsonify({"message": "Message status updated successfully"}), 200
        
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
        return jsonify({"message": "Message deleted successfully"}), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 400

# GET USER ANALYTICS ROUTE
@app.route('/analytics/users', methods=['GET'])
@login_required
def get_user_analytics():
    current_user = request.user
    if current_user.get("role") != "SuperAdmin":
        return jsonify({"message": "Only SuperAdmin can view analytics"}), 403

    try:
        # Get all users with timestamps
        users = list(users_collection.find({}, {"password": 0}))
        
        # Calculate time-based statistics
        now = datetime.datetime.utcnow()
        one_week_ago = now - datetime.timedelta(days=7)
        one_month_ago = now - datetime.timedelta(days=30)
        
        # Count users by time periods
        weekly_users = 0
        monthly_users = 0
        total_users = len(users)
        
        # Monthly data for charts (last 12 months)
        monthly_data = []
        for i in range(11, -1, -1):
            month_start = datetime.datetime(now.year, now.month - i, 1) if now.month > i else datetime.datetime(now.year - 1, 12 + now.month - i, 1)
            if i == 0:
                month_end = now
            else:
                next_month = month_start.month + 1 if month_start.month < 12 else 1
                next_year = month_start.year if month_start.month < 12 else month_start.year + 1
                month_end = datetime.datetime(next_year, next_month, 1)
            
            month_count = 0
            for user in users:
                if user.get('createdAt') and month_start <= user['createdAt'] < month_end:
                    month_count += 1
            monthly_data.append(month_count)
        
        # Weekly data for charts (last 7 days)
        weekly_data = []
        for i in range(6, -1, -1):
            day_start = datetime.datetime.combine(now.date() - datetime.timedelta(days=i), datetime.time.min)
            day_end = day_start + datetime.timedelta(days=1)
            
            day_count = 0
            for user in users:
                if user.get('createdAt') and day_start <= user['createdAt'] < day_end:
                    day_count += 1
            weekly_data.append(day_count)
        
        # Count weekly and monthly users
        for user in users:
            if user.get('createdAt'):
                if user['createdAt'] >= one_week_ago:
                    weekly_users += 1
                if user['createdAt'] >= one_month_ago:
                    monthly_users += 1
        
        # Prepare response
        analytics_data = {
            "weeklyUsers": weekly_users,
            "monthlyUsers": monthly_users,
            "totalUsers": total_users,
            "monthlyData": monthly_data,
            "weeklyData": weekly_data,
            "userGrowthRate": {
                "weekly": round((weekly_users / max(total_users - weekly_users, 1)) * 100, 2),
                "monthly": round((monthly_users / max(total_users - monthly_users, 1)) * 100, 2)
            }
        }
        
        return jsonify(analytics_data), 200
        
    except Exception as e:
        return jsonify({"message": f"Error calculating analytics: {str(e)}"}), 500

# GET MESSAGE ANALYTICS ROUTE
@app.route('/analytics/messages', methods=['GET'])
@login_required
def get_message_analytics():
    current_user = request.user
    if current_user.get("role") != "admin":
        return jsonify({"message": "Only Admin can view message analytics"}), 403

    try:
        # Get all messages with timestamps
        messages = list(messages_collection.find())
        
        # Calculate time-based statistics
        now = datetime.datetime.utcnow()
        one_week_ago = now - datetime.timedelta(days=7)
        one_month_ago = now - datetime.timedelta(days=30)
        
        # Count messages by time periods
        weekly_messages = 0
        monthly_messages = 0
        total_messages = len(messages)
        unread_messages = 0
        acknowledged_messages = 0
        
        # Count by status
        for message in messages:
            if message.get('status') == 'unread':
                unread_messages += 1
            elif message.get('status') == 'acknowledged':
                acknowledged_messages += 1
            
            # Count by time period
            if message.get('timestamp'):
                message_date = message['timestamp']
                if isinstance(message_date, str):
                    message_date = datetime.datetime.fromisoformat(message_date.replace('Z', '+00:00'))
                
                if message_date >= one_week_ago:
                    weekly_messages += 1
                if message_date >= one_month_ago:
                    monthly_messages += 1
        
        # Monthly data for charts (last 12 months)
        monthly_data = []
        for i in range(11, -1, -1):
            month_start = datetime.datetime(now.year, now.month - i, 1) if now.month > i else datetime.datetime(now.year - 1, 12 + now.month - i, 1)
            if i == 0:
                month_end = now
            else:
                next_month = month_start.month + 1 if month_start.month < 12 else 1
                next_year = month_start.year if month_start.month < 12 else month_start.year + 1
                month_end = datetime.datetime(next_year, next_month, 1)
            
            month_count = 0
            for message in messages:
                if message.get('timestamp'):
                    message_date = message['timestamp']
                    if isinstance(message_date, str):
                        message_date = datetime.datetime.fromisoformat(message_date.replace('Z', '+00:00'))
                    
                    if month_start <= message_date < month_end:
                        month_count += 1
            monthly_data.append(month_count)
        
        # Weekly data for charts (last 7 days)
        weekly_data = []
        for i in range(6, -1, -1):
            day_start = datetime.datetime.combine(now.date() - datetime.timedelta(days=i), datetime.time.min)
            day_end = day_start + datetime.timedelta(days=1)
            
            day_count = 0
            for message in messages:
                if message.get('timestamp'):
                    message_date = message['timestamp']
                    if isinstance(message_date, str):
                        message_date = datetime.datetime.fromisoformat(message_date.replace('Z', '+00:00'))
                    
                    if day_start <= message_date < day_end:
                        day_count += 1
            weekly_data.append(day_count)
        
        # Crime type analysis
        crime_types = {}
        for message in messages:
            crime_type = "Unknown"
            if message.get('payload') and message['payload'].get('message'):
                crime_type = message['payload']['message']
            
            crime_types[crime_type] = crime_types.get(crime_type, 0) + 1
        
        # Calculate growth rates
        previous_week_messages = 0
        previous_month_messages = 0
        two_weeks_ago = now - datetime.timedelta(days=14)
        two_months_ago = now - datetime.timedelta(days=60)
        
        for message in messages:
            if message.get('timestamp'):
                message_date = message['timestamp']
                if isinstance(message_date, str):
                    message_date = datetime.datetime.fromisoformat(message_date.replace('Z', '+00:00'))
                
                if two_weeks_ago <= message_date < one_week_ago:
                    previous_week_messages += 1
                if two_months_ago <= message_date < one_month_ago:
                    previous_month_messages += 1
        
        # Prepare response
        analytics_data = {
            "weeklyMessages": weekly_messages,
            "monthlyMessages": monthly_messages,
            "totalMessages": total_messages,
            "unreadMessages": unread_messages,
            "acknowledgedMessages": acknowledged_messages,
            "monthlyData": monthly_data,
            "weeklyData": weekly_data,
            "crimeTypes": crime_types,
            "messageGrowthRate": {
                "weekly": round(((weekly_messages - previous_week_messages) / max(previous_week_messages, 1)) * 100, 2),
                "monthly": round(((monthly_messages - previous_month_messages) / max(previous_month_messages, 1)) * 100, 2)
            }
        }
        
        return jsonify(analytics_data), 200
        
    except Exception as e:
        return jsonify({"message": f"Error calculating message analytics: {str(e)}"}), 500

# Home or test endpoint
@app.route('/', methods=['GET'])
def home():
    print(api_key, url, sender, receivers, mongo_db_base)
    return jsonify({"message": "Welcome to ShieldUp Auth API"}), 200

if __name__ == '__main__':
    app.run(debug=True)