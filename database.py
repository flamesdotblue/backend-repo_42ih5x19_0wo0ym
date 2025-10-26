import os
import datetime
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

DATABASE_URL = os.getenv("DATABASE_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "appdb")

_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None


def _get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(DATABASE_URL)
    return _client


def db() -> AsyncIOMotorDatabase:
    global _db
    if _db is None:
        _db = _get_client()[DATABASE_NAME]
    return _db


async def create_document(collection_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
    now = datetime.datetime.utcnow()
    doc = {**data, "created_at": now, "updated_at": now}
    result = await db()[collection_name].insert_one(doc)
    doc["_id"] = str(result.inserted_id)
    return doc


async def get_documents(
    collection_name: str,
    filter_dict: Optional[Dict[str, Any]] = None,
    limit: int = 50,
    sort: Optional[List] = None,
) -> List[Dict[str, Any]]:
    filter_dict = filter_dict or {}
    cursor = db()[collection_name].find(filter_dict)
    if sort:
        cursor = cursor.sort(sort)
    if limit:
        cursor = cursor.limit(limit)
    items: List[Dict[str, Any]] = []
    async for item in cursor:
        item["_id"] = str(item["_id"])  # string-ify ObjectId
        items.append(item)
    return items
