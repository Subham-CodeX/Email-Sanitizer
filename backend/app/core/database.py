from typing import Optional
from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase
from app.core.config import settings

class MongoDB:
    client: Optional[AsyncMongoClient] = None
    db: Optional[AsyncDatabase] = None

mongodb = MongoDB()

async def connect_to_mongo():
    mongodb.client = AsyncMongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=5000)
    await mongodb.client.admin.command("ping")
    mongodb.db = mongodb.client[settings.mongodb_db]
    print("✓ MongoDB connected")

async def close_mongo_connection():
    if mongodb.client is not None:
        await mongodb.client.close()
        mongodb.client = None
        mongodb.db = None
        print("✓ MongoDB connection closed")

def get_database() -> AsyncDatabase:
    if mongodb.db is None:
        raise RuntimeError("MongoDB is not initialized.")
    return mongodb.db
