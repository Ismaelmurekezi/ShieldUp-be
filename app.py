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
import threading
import paho.mqtt.client as mqtt
import json
import requests
import time

# Load environment variables from .env file
load_dotenv(find_dotenv())
mongo_db = os.environ.get("MONGODB_URL")
jwt_secret = os.environ.get("JWT_SECRET_KEY")
api_key = os.environ.get("HTTPSMS_API_KEY")
url = os.environ.get("HTTPSMS_URL")
sender = "+250781530573"
receivers =["+250788911633", "+250791356646","+0783447260"]
mongo_db_base = os.environ.get("MONGODB_URL_BASE")

app = Flask(__name__)
CORS(app,
     supports_credentials=True,
     resources={r"/*": {"origins": [
         "http://localhost:5173",
         "https://ibhews.netlify.app"
     ]}},
     allow_headers=["Content-Type", "Authorization"],
     expose_headers=["Content-Type", "Set-Cookie"], 
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)
app.config["MONGO_URI"] = mongo_db
app.config["SECRET_KEY"] = jwt_secret

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
users_collection = mongo.db.users
messages_collection = mongo.db.messages

# MQTT and SMS functionality
class MQTTHandler:
    def __init__(self):
        self.client = None
        self.mongo_client = None
        self.db = None
        self.collection = None
        self.headers = {
            'x-api-key': api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
    def setup_mongodb(self):
        """Setup MongoDB connection for MQTT messages"""
        try:
            self.mongo_client = pymongo.MongoClient(mongo_db_base)
            self.db = self.mongo_client["mqtt_logs"]
            self.collection = self.db["messages"]
            print("MQTT MongoDB connection established")
        except Exception as e:
            print(f"Failed to connect to MQTT MongoDB: {e}")
    
    def send_sms(self, payload):
        """Send SMS via HTTPSMS API"""
        try:
            response = requests.post(url, headers=self.headers, data=json.dumps(payload))
            if response.status_code == 200:
                print("SMS sent successfully!")
                time.sleep(1)
            else:
                print(f"Failed to send SMS: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"SMS sending error: {str(e)}")

    def on_connect(self, client, userdata, flags, rc):
        """Callback for when MQTT client connects"""
        if rc == 0:
            print("Connected to MQTT broker")
            client.subscribe("device/+/inbox")
            print("Subscribed to device/+/inbox")
        else:
            print(f"Failed to connect to MQTT broker with code {rc}")

    def on_message(self, client, userdata, msg):
        """Handle incoming MQTT messages"""
        try:
            payload = json.loads(msg.payload.decode())
            topic = msg.topic
            print(f"Received message on topic {topic}: {payload}")

            # Handle acknowledgment message
            if "acknowledge" in payload and payload["acknowledge"] == True:
                message_id = payload.get("message_id")
                print(f"Acknowledgment received for message ID: {message_id}")

                # Update the message status to "acknowledged"
                result = self.collection.find_one_and_update(
                    {"topic": "device/esp1/inbox", "status": "unread", "message_id": message_id},
                    {"$set": {"status": "acknowledged", "acknowledged_at": datetime.datetime.utcnow()}},
                    sort=[("timestamp", -1)]
                )
                if result:
                    print(f"Message updated to 'acknowledged': {result.get('_id')}")
                else:
                    print("No unread message found with this ID to acknowledge.")
                return

            # Log new messages
            log = {
                "topic": topic,
                "payload": payload,
                "timestamp": datetime.datetime.utcnow(),
                "status": "unread",
                "message_id": payload.get("message_id")
            }
            self.collection.insert_one(log)
            print(f"Logged message: {log}")

            # Send SMS notifications
            if receivers:
                receiver_list = receivers if isinstance(receivers, list) else receivers.split(',')
                for receiver in receiver_list:
                    receiver = receiver.strip()
                    msg_payload = {
                        "content": f"Crime type: {payload.get('message', 'Unknown')}\nLocation: {payload.get('location', 'Unknown')}\nFrom: {payload.get('from', 'Unknown')}\nCoordinates: https://www.google.com/maps/search/?api=1&query={payload.get('cords', '').split(' ')[0] if payload.get('cords') else ''}",
                        "from": sender,
                        "to": receiver
                    }
                    # Send SMS in a separate thread to avoid blocking
                    threading.Thread(target=self.send_sms, args=[msg_payload], daemon=True).start()

        except Exception as e:
            print(f"Error processing MQTT message: {str(e)}")

    def on_disconnect(self, client, userdata, rc):
        """Callback for when MQTT client disconnects"""
        print(f"Disconnected from MQTT broker with code {rc}")

    def start_mqtt_client(self):
        """Start the MQTT client"""
        try:
            self.setup_mongodb()
            
            self.client = mqtt.Client()
            self.client.on_connect = self.on_connect
            self.client.on_message = self.on_message
            self.client.on_disconnect = self.on_disconnect
            
            # Connect to MQTT broker
            print("Connecting to MQTT broker...")
            self.client.connect("localhost", 1883, 60)
            
            # Start the loop in a non-blocking way
            self.client.loop_forever()
            
        except Exception as e:
            print(f"MQTT client error: {str(e)}")
            # Retry connection after 30 seconds
            time.sleep(30)
            self.start_mqtt_client()

# Initialize MQTT handler
mqtt_handler = MQTTHandler()

def start_mqtt_service():
    """Start MQTT service in a separate thread"""
    print("🚀 Starting MQTT service...")
    mqtt_handler.start_mqtt_client()

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
        print("SuperAdmin created")
    else:
        print("ℹSuperAdmin already exists")

create_superadmin()

# Middleware to protect routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get("access_token")
        
        # Add fallback to check Authorization header
        if not token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        
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
    
    # Get the origin from the request
    origin = request.headers.get('Origin')
    print(f"Request origin: {origin}")
    print(f"Request host: {request.host}")
    
    # Set CORS headers
    if origin and origin in ["http://localhost:5173", "https://ibhews.netlify.app"]:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'Set-Cookie'
        print(f"CORS headers set for origin: {origin}")
    
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        secure=True, 
        samesite="None",
        max_age=24*60*60,
        path='/',
        domain=None 
    )
    
    print(f"Cookie set: access_token with secure=True, samesite=None")
    return response, 200

# Debug endpoint to check cookie and request details
@app.route('/debug/auth', methods=['GET'])
def debug_auth():
    cookies = dict(request.cookies)
    headers = dict(request.headers)
    
    return jsonify({
        "cookies": cookies,
        "has_access_token": "access_token" in cookies,
        "origin": headers.get('Origin'),
        "host": request.host,
        "user_agent": headers.get('User-Agent'),
        "referer": headers.get('Referer'),
        "is_https": request.is_secure,
        "scheme": request.scheme,
        "all_headers": headers
    })

# GET ALL USERS ROUTE
@app.route('/users', methods=['GET'])
@login_required
def get_all_users():
    current_user = request.user
    if current_user.get("role") != "SuperAdmin":
        return jsonify({"message": "Only SuperAdmin can view all users"}), 403

    try:
        # Get pagination parameters from query string
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10)) 
        skip = (page - 1) * limit

        # Get total count for pagination info
        total_users = users_collection.count_documents({})

      
        users = list(users_collection.find({}, {"password": 0})
                    .skip(skip)
                    .limit(limit)
                    .sort("createdAt", -1))  
        
        # Convert ObjectId to string
        for user in users:
            user["_id"] = str(user["_id"])

        # Calculate pagination info
        total_pages = (total_users + limit - 1) // limit
        pagination_info = {
            "currentPage": page,
            "totalPages": total_pages,
            "totalUsers": total_users,
            "limit": limit,
            "hasNext": page < total_pages,
            "hasPrev": page > 1
        }

        return jsonify({
            "users": users,
            "pagination": pagination_info
        }), 200

    except ValueError:
        return jsonify({"message": "Invalid page or limit parameter"}), 400
    except Exception as e:
        return jsonify({"message": f"Error fetching users: {str(e)}"}), 500

# GET SINGLE USER ROUTE
@app.route('/users/<user_id>', methods=['GET'])
@login_required
def get_user_by_id(user_id):
    current_user = request.user
    if current_user.get("role") != "SuperAdmin":
        return jsonify({"message": "Only SuperAdmin can view user details"}), 403

    if not ObjectId.is_valid(user_id):
        return jsonify({"message": "Invalid user ID"}), 400

    user = users_collection.find_one({"_id": ObjectId(user_id)}, {"password": 0}) 
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
    
    # Get the origin from the request
    origin = request.headers.get('Origin')
    
    # Set CORS headers
    if origin and origin in ["http://localhost:5173", "https://ibhews.netlify.app"]:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    # Clear the JWT cookie with same settings as when it was set
    response.set_cookie(
        "access_token", 
        "", 
        httponly=True, 
        secure=True, 
        samesite="None", 
        expires=0,
        path='/',
        domain=None
    )
    
    return response, 200

# Get all messages with pagination
@app.route('/messages', methods=['GET'])
@login_required
def get_all_messages():
    current_user = request.user
    if current_user.get("role") != "admin":
        return jsonify({"message": "Only Admin can see messages"}), 403

    try:
        user_sector = current_user.get("sector")
        if not user_sector:
            return jsonify({"message": "User sector not found"}), 400

        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        skip = (page - 1) * limit

        pipeline = [
            {
                "$addFields": {
                    "sector": {
                        "$arrayElemAt": [
                            { "$split": ["$payload.location", "-"] },
                            1
                        ]
                    }
                }
            },
            { "$match": { "sector": user_sector } },
            { "$sort": { "timestamp": -1 } },
            { "$skip": skip },
            { "$limit": limit }
        ]

        messages = list(messages_collection.aggregate(pipeline))

        # Update count query to also use payload.location
        total_filtered = messages_collection.count_documents({
            "payload.location": { "$regex": f"^[^-]+-{user_sector}-" }
        })

        for msg in messages:
            msg["_id"] = str(msg["_id"])

        total_pages = (total_filtered + limit - 1) // limit
        pagination_info = {
            "currentPage": page,
            "totalPages": total_pages,
            "totalMessages": total_filtered,
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
        user_sector = current_user.get("sector")
        if not user_sector:
            return jsonify({"message": "User sector not found"}), 400

        # Filter messages by sector extracted from payload.location
        pipeline = [
            {
                "$addFields": {
                    "sector": {
                        "$arrayElemAt": [
                            { "$split": ["$payload.location", "-"] },
                            1
                        ]
                    }
                }
            },
            { "$match": { "sector": user_sector } }
        ]

        messages = list(messages_collection.aggregate(pipeline))
        
        now = datetime.datetime.utcnow()
        one_week_ago = now - datetime.timedelta(days=7)
        one_month_ago = now - datetime.timedelta(days=30)
        two_weeks_ago = now - datetime.timedelta(days=14)
        two_months_ago = now - datetime.timedelta(days=60)

        weekly_messages = 0
        monthly_messages = 0
        unread_messages = 0
        acknowledged_messages = 0
        total_messages = len(messages)

        monthly_data = [0] * 12
        weekly_data = [0] * 7
        crime_types = {}
        previous_week_messages = 0
        previous_month_messages = 0

        # New: Initialize crime types by month
        crime_types_by_month = {}

        for month_idx in range(12):
            month_start = datetime.datetime(now.year, now.month - (11 - month_idx), 1) if now.month > (11 - month_idx) else datetime.datetime(now.year - 1, 12 + now.month - (11 - month_idx), 1)
            month_end = month_start + datetime.timedelta(days=32)
            month_end = month_end.replace(day=1)
            
            month_data = {
                "monthIndex": month_idx,
                "burglary": 0,
                "armedRobbery": 0,
                "theft": 0
            }
            
            crime_types_by_month[month_idx] = month_data

        for message in messages:
            ts = message.get('timestamp')
            if isinstance(ts, str):
                ts = datetime.datetime.fromisoformat(ts.replace('Z', '+00:00'))

            if not ts:
                continue

            # Status counts
            if message.get('status') == 'unread':
                unread_messages += 1
            elif message.get('status') == 'acknowledged':
                acknowledged_messages += 1

            # Weekly & monthly counts
            if ts >= one_week_ago:
                weekly_messages += 1
            if ts >= one_month_ago:
                monthly_messages += 1

            if two_weeks_ago <= ts < one_week_ago:
                previous_week_messages += 1
            if two_months_ago <= ts < one_month_ago:
                previous_month_messages += 1

            # Monthly distribution
            month_index = (now.year - ts.year) * 12 + now.month - ts.month
            if 0 <= month_index < 12:
                monthly_data[11 - month_index] += 1

            # Weekly distribution
            day_diff = (now.date() - ts.date()).days
            if 0 <= day_diff < 7:
                weekly_data[6 - day_diff] += 1

            # Crime type count
            crime = message.get('payload', {}).get('message', 'Unknown')
            crime_types[crime] = crime_types.get(crime, 0) + 1

            # Categorize crime by type for monthly breakdown
            crime_lower = crime.lower()
            month_index = (now.year - ts.year) * 12 + now.month - ts.month
            if 0 <= month_index < 12:
                if 'burglary' in crime_lower:
                    crime_types_by_month[11 - month_index]['burglary'] += 1
                elif 'armed' in crime_lower or 'robbery' in crime_lower:
                    crime_types_by_month[11 - month_index]['armedRobbery'] += 1
                elif 'theft' in crime_lower:
                    crime_types_by_month[11 - month_index]['theft'] += 1

        analytics_data = {
            "weeklyMessages": weekly_messages,
            "monthlyMessages": monthly_messages,
            "totalMessages": total_messages,
            "unreadMessages": unread_messages,
            "acknowledgedMessages": acknowledged_messages,
            "monthlyData": monthly_data,
            "weeklyData": weekly_data,
            "crimeTypes": crime_types,
            "crimeTypesByMonth": list(crime_types_by_month.values()),
            "messageGrowthRate": {
                "weekly": round(((weekly_messages - previous_week_messages) / max(previous_week_messages, 1)) * 100, 2),
                "monthly": round(((monthly_messages - previous_month_messages) / max(previous_month_messages, 1)) * 100, 2)
            }
        }

        return jsonify(analytics_data), 200

    except Exception as e:
        return jsonify({"message": f"Error calculating message analytics: {str(e)}"}), 500



# MQTT Status endpoint
@app.route('/mqtt/status', methods=['GET'])
@login_required
def get_mqtt_status():
    """Get MQTT service status"""
    current_user = request.user
    if current_user.get("role") not in ["admin", "SuperAdmin"]:
        return jsonify({"message": "Unauthorized"}), 403
    
    status = {
        "mqtt_connected": mqtt_handler.client.is_connected() if mqtt_handler.client else False,
        "mongodb_connected": mqtt_handler.mongo_client is not None,
        "service_running": True
    }
    return jsonify(status), 200

# Home or test endpoint
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "message": "Welcome to ShieldUp Auth API with MQTT Integration",
        "services": {
            "flask_api": "running",
            "mqtt_client": "running" if mqtt_handler.client else "starting",
            "sms_service": "enabled" if api_key and url else "disabled"
        }
    }), 200

if __name__ == '__main__':
    # Start MQTT service in a separate daemon thread
    mqtt_thread = threading.Thread(target=start_mqtt_service, daemon=True)
    mqtt_thread.start()
    
    print("🚀 Starting Flask application with MQTT integration...")
    print(f"📱 SMS Service: {'Enabled' if api_key and url else 'Disabled'}")
    print(f"📊 MongoDB: {'Connected' if mongo_db else 'Not configured'}")
    
    # Start Flask app
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
