import paho.mqtt.client as mqtt
import pymongo
import json
from datetime import datetime
import requests
import json
import threading


api_key = "MNKpy5NcYeSY9f28TvEp2WKe2lVRkOhtIUpc0w0bz6BRZplKuMMhPdoMyw5xSP91"

url = 'https://api.httpsms.com/v1/messages/send'

headers = {
    'x-api-key': api_key,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}




def send_message(payload):
    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        if response.status_code == 200:
            print("✅ Message sent successfully!")
        else:
            print(f"⚠️ Failed to send message: {response.status_code} - {response.text}")
    except Exception as e:
        print(str(e))
# MongoDB setup
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["mqtt_logs"]
collection = db["messages"]

def on_message(client, userdata, msg):
    payload = json.loads(msg.payload.decode())
    topic = msg.topic

    # Handle acknowledgment message
    if "acknowledge" in payload and payload["acknowledge"] == True:
        message_id = payload.get("message_id")
        print(f"✅ Acknowledgment received for message ID: {message_id}")

        # Update the message status to "acknowledged"
        result = collection.find_one_and_update(
            {"topic": "device/esp1/inbox", "status": "unread", "message_id": message_id},
            {"$set": {"status": "acknowledged", "acknowledged_at": datetime.utcnow()}},
            sort=[("timestamp", -1)]
        )
        if result:
            print(f"📝 Message updated to 'acknowledged': {result.get('_id')}")
        else:
            print("⚠️ No unread message found with this ID to acknowledge.")
        return

    else:
        # Log new messages
        log = {
            "topic": topic,
            "payload": payload,
            "timestamp": datetime.utcnow(),
            "status": "unread",
            "message_id": payload.get("message_id")
        }
        collection.insert_one(log)
        print(f"📥 Logged message: {log}")
        payload = {
            "content": payload["message"],
            "from": "+250791105800",
            "to": "+250732657995"
        }
        message_thread= threading.Thread(target=send_message, args=[payload])
        message_thread.start()

# MQTT setup
mqttc = mqtt.Client()
mqttc.on_message = on_message
mqttc.connect("localhost", 1883)
mqttc.subscribe("device/+/inbox")
print("✅ Connected to MQTT broker. Waiting for messages...")
mqttc.loop_forever()
