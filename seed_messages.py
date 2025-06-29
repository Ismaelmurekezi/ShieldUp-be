import datetime
import random
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
import os

load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL")
client = MongoClient(MONGODB_URL)
db = client.get_database()
messages_collection = db["messages"]

# Possible sample values
names = ["Claire", "John", "Alice", "Ben", "Grace", "Ishimwe", "Eric", "Anna", "David", "Linda"]
crimes = ["Armed Robbery", "Burglary", "Theft"]
locations = [
    "Nyarugenge-Gitega-Gitega-Indatwa",
    "Nyarugenge-Gitega-Kanyinya-Kabeza",
    "Nyarugenge-Nyamirambo-Kivugiza-Mwurire",
    "Nyarugenge-Rwezamenyo-Rwezamenyo1-Indatwa",
    "Nyarugenge-Rwezamenyo-Rwezamenyo1-Abatarushwa"
]

# Helper to generate random coordinates and ID suffix
def generate_coords_and_id():
    lat = round(random.uniform(-2.0, -1.8), 7)
    lon = round(random.uniform(29.9, 30.2), 7)
    id_suffix = random.randint(10000, 99999)
    return f"{lat},{lon} KIG_{id_suffix}", str(id_suffix)

# Build 20 seed messages
messages = []
base_time = datetime.datetime.utcnow()

for i in range(20):
    name = random.choice(names)
    crime = random.choice(crimes)
    location = random.choice(locations)
    coords, msg_id = generate_coords_and_id()
    timestamp = base_time - datetime.timedelta(minutes=i * 7)
    ack_time = timestamp + datetime.timedelta(minutes=5)

    message = {
        "_id": ObjectId(),
        "topic": f"device/{name}/inbox",
        "payload": {
            "from": name,
            "message": crime,
            "message_id": msg_id,
            "location": location,
            "cords": coords
        },
        "timestamp": timestamp,
        "status": "acknowledged",
        "message_id": msg_id,
        "acknowledged_at": ack_time
    }
    messages.append(message)

# Insert into MongoDB
result = messages_collection.insert_many(messages)
print(f"✅ Inserted {len(result.inserted_ids)} messages.")
