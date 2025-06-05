import paho.mqtt.client as mqtt
import pymongo
import json
from datetime import datetime
import requests
import json
import time
from dotenv import load_dotenv, find_dotenv
import os


# Load environment variables from .env file
load_dotenv(find_dotenv())
mongo_db_base = os.environ.get("MONGODB_URL_BASE")
api_key = os.environ.get("HTTPSMS_API_KEY")
url = os.environ.get("HTTPSMS_URL")
sender = os.environ.get("HTTPSMS_SENDER")
receivers = os.environ.get("HTTPSMS_RECEIVERS")




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
            time.sleep(1)
        else:
            print(f"⚠️ Failed to send message: {response.status_code} - {response.text}")
    except Exception as e:
        print(str(e))

# MongoDB setup
client = pymongo.MongoClient(mongo_db_base)
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
       
        log = {
            "topic": topic,
            "payload": payload,
            "timestamp": datetime.utcnow(),
            "status": "unread",
            "message_id": payload.get("message_id")
        }
        collection.insert_one(log)
        print(f"📥 Logged message: {log}")
        for reveiver in receivers:
             # Log new messages
       
            msg_payload = {
                "content": f"Crime type: {payload["message"]}\n\rLocation: {payload["location"]}\n\rFrom: {payload["from"]} \n\r cordinates: https://www.google.com/maps/search/?api=1&query={payload["cords"].split(" ")[0]}",
                "from": sender,
                "to": reveiver
            }
            send_message(msg_payload)
            # message_thread= threading.Thread(target=send_message, args=[msg_payload])
            # message_thread.start()
# MQTT setup
mqttc = mqtt.Client()
mqttc.on_message = on_message
mqttc.connect("localhost", 1883)
mqttc.subscribe("device/+/inbox")
print("✅ Connected to MQTT broker. Waiting for messages...")
mqttc.loop_forever()
