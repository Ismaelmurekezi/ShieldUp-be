import datetime
import random
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from dotenv import load_dotenv, find_dotenv
import os

# Load environment variables
load_dotenv(find_dotenv())
mongo_db = os.environ.get("MONGODB_URL")

# Initialize MongoDB connection
client = MongoClient(mongo_db)
db = client.get_default_database()
users_collection = db.users

# Initialize bcrypt
bcrypt = Bcrypt()

# Kigali Districts and their actual sectors
KIGALI_LOCATIONS = {
    "Gasabo": [
        "Bumbogo", "Gatsata", "Gikomero", "Gisozi", "Jabana", "Jali", 
        "Kacyiru", "Kimihurura", "Kimisagara", "Kinyinya", "Ndera", 
        "Nduba", "Remera", "Rusororo", "Rutunga"
    ],
    "Kicukiro": [
        "Gahanga", "Gatenga", "Gikondo", "Kagarama", "Kanombe", 
        "Kicukiro", "Kigarama", "Masaka", "Niboye", "Nyarugunga"
    ],
    "Nyarugenge": [
        "Gitega", "Kanyinya", "Kigali", "Kimisagara", "Mageragere", 
        "Muhima", "Nyakabanda", "Nyamirambo", "Nyarugenge", "Rwezamenyo"
    ]
}

# Sample first names (mix of Rwandan and international names)
FIRST_NAMES = [
    "Jean", "Marie", "Pierre", "Alice", "David", "Grace", "Paul", "Rose", "Claude", "Agnes",
    "Emmanuel", "Solange", "Vincent", "Jeanne", "Eric", "Francine", "Patrick", "Immaculee",
    "Joseph", "Esperance", "Gilbert", "Vestine", "Augustin", "Chantal", "Innocent", "Beatrice",
    "Martin", "Consolee", "Felix", "Clementine", "Eugene", "Josephine", "Andre", "Bernadette",
    "Charles", "Goretti", "Michel", "Speciose", "Bernard", "Jacqueline", "Leopold", "Alphonsine",
    "Antoine", "Drocelle", "Celestin", "Stephanie", "Olivier", "Valentine", "Fabrice", "Claudine",
    "Samuel", "Rosette", "Robert", "Odette", "Thomas", "Marthe", "Francis", "Josepha",
    "Daniel", "Annunciata", "Pascal", "Xaverine"
]

# Sample last names (common Rwandan surnames)
LAST_NAMES = [
    "Uwimana", "Murenzi", "Habimana", "Nzeyimana", "Nsengimana", "Mukamana", "Uwamahoro", "Bizimana",
    "Ntakirutimana", "Mukeshimana", "Niyonsenga", "Uwizeye", "Mukamukama", "Niyonkuru", "Uwingabire",
    "Bizumuremyi", "Mukasine", "Nzabonimpa", "Uwamungu", "Bizimungu", "Mukamuganga", "Nzayisenga",
    "Uwingabiye", "Bizimuremyi", "Mukamana", "Nzabonimana", "Uwimana", "Bizimana", "Mukashema",
    "Niyonkuru", "Uwamahoro", "Bizumuremyi", "Mukamukama", "Nzeyimana", "Uwizeye", "Bizimungu",
    "Mukasine", "Nzabonimpa", "Uwamungu", "Bizimana", "Mukamuganga", "Nzayisenga", "Uwingabiye",
    "Bizimuremyi", "Mukamana", "Nzabonimana", "Uwimana", "Bizimana", "Mukashema", "Niyonkuru",
    "Uwamahoro", "Bizumuremyi", "Mukamukama", "Nzeyimana", "Uwizeye", "Bizimungu", "Mukasine",
    "Nzabonimpa", "Uwamungu", "Bizimana", "Mukamuganga"
]

def generate_user_data(month_index, user_index):
    """Generate user data for a specific month and user index"""
    
    # Create registration date within the specified month of 2024
    year = 2024
    month = month_index + 1  # month_index is 0-11, but months are 1-12
    
    # Random day within the month
    if month in [1, 3, 5, 7, 8, 10, 12]:
        max_day = 31
    elif month in [4, 6, 9, 11]:
        max_day = 30
    else:  # February
        max_day = 29 if year % 4 == 0 else 28
    
    day = random.randint(1, max_day)
    hour = random.randint(8, 18)  # Business hours
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    
    created_at = datetime.datetime(year, month, day, hour, minute, second)
    
    # Generate random name
    first_name = random.choice(FIRST_NAMES)
    last_name = random.choice(LAST_NAMES)
    username = f"{first_name.lower()}.{last_name.lower()}"
    
    # Generate email
    email_domains = ["gmail.com", "yahoo.com", "shieldup.rw", "gov.rw", "outlook.com"]
    email = f"{username}{user_index}@{random.choice(email_domains)}"
    
    # Select random district and sector from Kigali only
    district = random.choice(list(KIGALI_LOCATIONS.keys()))
    sector = random.choice(KIGALI_LOCATIONS[district])
    
    # Hash password (default: "password123")
    password = "password123"
    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    
    # Add some variation to update times (some users updated their profiles)
    updated_at = created_at
    if random.random() < 0.3:  # 30% chance user updated their profile
        # Add random days between creation and now
        days_to_add = random.randint(1, 150)
        updated_at = created_at + datetime.timedelta(days=days_to_add)
    
    # Add last login data for some users
    last_login_at = None
    if random.random() < 0.7:  # 70% chance user has logged in
        # Random login between creation and now
        days_since_creation = (datetime.datetime.utcnow() - created_at).days
        if days_since_creation > 0:
            login_days_after = random.randint(0, min(days_since_creation, 30))
            last_login_at = created_at + datetime.timedelta(days=login_days_after)
    
    return {
        "username": username,
        "email": email,
        "password": hashed_pw,
        "role": "admin",
        "district": district,
        "sector": sector,
        "createdAt": created_at,
        "updatedAt": updated_at,
        "lastLoginAt": last_login_at
    }

def seed_users():
    """Create 60 users distributed across 12 months (5 users per month)"""
    
    print(" Starting user seeding process...")
    
    # Check if users already exist (excluding superadmin)
    existing_users = users_collection.count_documents({"role": {"$ne": "SuperAdmin"}})
    if existing_users > 0:
        print(f"  Found {existing_users} existing users. Do you want to continue? (y/n)")
        response = input().lower()
        if response != 'y':
            print(" Seeding cancelled.")
            return
        
        # Clear existing admin users
        result = users_collection.delete_many({"role": {"$ne": "SuperAdmin"}})
        print(f"🗑️  Deleted {result.deleted_count} existing admin users.")
    
    users_to_insert = []
    users_per_month = 5
    
    for month_index in range(12):  # 0-11 for 12 months
        month_name = datetime.datetime(2024, month_index + 1, 1).strftime("%B")
        print(f" Generating users for {month_name} 2024...")
        
        for user_index in range(users_per_month):
            user_data = generate_user_data(month_index, month_index * users_per_month + user_index)
            users_to_insert.append(user_data)
    
    # Insert all users at once
    try:
        result = users_collection.insert_many(users_to_insert)
        print(f" Successfully created {len(result.inserted_ids)} users!")
        
        # Display summary
        print("\n SEEDING SUMMARY:")
        print(f"Total users created: {len(result.inserted_ids)}")
        print("Distribution by month:")
        
        for month_index in range(12):
            month_name = datetime.datetime(2024, month_index + 1, 1).strftime("%B")
            count = users_collection.count_documents({
                "createdAt": {
                    "$gte": datetime.datetime(2024, month_index + 1, 1),
                    "$lt": datetime.datetime(2024, month_index + 2, 1) if month_index < 11 else datetime.datetime(2025, 1, 1)
                }
            })
            print(f"  {month_name}: {count} users")
        
        # Display sample users
        print("\n SAMPLE USERS CREATED:")
        sample_users = users_collection.find({"role": "admin"}).limit(5)
        for user in sample_users:
            print(f"   {user['email']} | {user['username']} | {user['district']}-{user['sector']} | Created: {user['createdAt'].strftime('%Y-%m-%d')}")
        
        print(f"\n Default password for all users: 'password123'")
        print("All users are located in Kigali districts: Gasabo, Kicukiro, Nyarugenge")
        print("You can now login with any of the generated email addresses!")
        
    except Exception as e:
        print(f" Error creating users: {str(e)}")

def display_user_stats():
    """Display statistics about created users"""
    total_users = users_collection.count_documents({"role": "admin"})
    
    if total_users == 0:
        print("📭 No admin users found. Run the seeder first!")
        return
    
    print(f"\n USER STATISTICS:")
    print(f"Total admin users: {total_users}")
    
    # Users by Kigali district
    print("\n Users by Kigali District:")
    pipeline = [
        {"$match": {"role": "admin"}},
        {"$group": {"_id": "$district", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    
    district_stats = list(users_collection.aggregate(pipeline))
    for stat in district_stats:
        print(f"  {stat['_id']}: {stat['count']} users")
    
    # Top sectors
    print("\n Top 10 Sectors:")
    sector_pipeline = [
        {"$match": {"role": "admin"}},
        {"$group": {"_id": "$sector", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]
    
    sector_stats = list(users_collection.aggregate(sector_pipeline))
    for stat in sector_stats:
        print(f"  {stat['_id']}: {stat['count']} users")
    
    # Users by month
    print("\n Users by Registration Month:")
    for month in range(1, 13):
        month_name = datetime.datetime(2024, month, 1).strftime("%B")
        count = users_collection.count_documents({
            "role": "admin",
            "createdAt": {
                "$gte": datetime.datetime(2024, month, 1),
                "$lt": datetime.datetime(2024, month + 1, 1) if month < 12 else datetime.datetime(2025, 1, 1)
            }
        })
        print(f"  {month_name}: {count} users")
    
    # Login statistics
    logged_in_users = users_collection.count_documents({
        "role": "admin", 
        "lastLoginAt": {"$exists": True, "$ne": None}
    })
    print(f"\n Users who have logged in: {logged_in_users}/{total_users}")

if __name__ == "__main__":
    print("🚀 ShieldUp User Seeder")
    print("=" * 50)
    
    while True:
        print("\nChoose an option:")
        print("1. Seed 60 users (5 per month)")
        print("2. Display user statistics")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            seed_users()
        elif choice == "2":
            display_user_stats()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
    
    # Close MongoDB connection
    client.close()