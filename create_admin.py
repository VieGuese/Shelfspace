from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from datetime import datetime

client = MongoClient("mongodb+srv://shelfspace:onlinebookstore@cluster0.msktkcg.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["ShelfSpace"]
users_collection = db["users"]

admin_doc = {
    "first_name": "Admin",
    "last_name": " ",
    "email": "admin@shelfspace.com",
    "username": "admin@shelfspace.com",
    "password": generate_password_hash("admin123"),
    "role": "admin",
    "created_at": datetime.utcnow(),
    "updated_at": datetime.utcnow()
}


result = users_collection.insert_one(admin_doc)
print("Admin user created! ID:", result.inserted_id)
