import os
import logging
from pymongo import MongoClient
from gridfs import GridFS
from bson import ObjectId
from dotenv import load_dotenv
from datetime import datetime
from flask import url_for

# Load environment variables from a .env file
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB connection setup
MONGO_URI ="mongodb+srv://ankitnayak7895:Ankitnodb@cluster0.62dva.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(MONGO_URI)
db = client['web_portal']
fs = GridFS(db)

# Collection for storing image metadata
images_collection = db['images']


def upload_file(file):
    """
    Upload a file to GridFS and store metadata in a separate collection.
    """
    if not file or file.filename == '':
        raise ValueError("No file provided or filename is empty.")

    try:
        file_contents = file.stream.read()  # ✅ Properly read file stream
        content_type = file.content_type or "application/octet-stream"
        
        file_id = fs.put(file_contents, filename=file.filename, content_type=content_type)

        # Save metadata
        images_collection.insert_one({
            "file_id": file_id,
            "filename": file.filename,
            "content_type": content_type,
            "created_at": datetime.utcnow()
        })

        logger.info(f"✅ File uploaded successfully with ID: {file_id}")
        return str(file_id)
    except Exception as e:
        logger.error(f"❌ File upload failed: {e}")
        raise


def get_file(file_id):
    """
    Retrieve a file from GridFS using its ID.
    """
    try:
        file = fs.get(ObjectId(file_id))
        logger.info(f"✅ File fetched with ID: {file_id}")
        return file
    except Exception as e:
        logger.error(f"❌ Failed to fetch file {file_id}: {e}")
        raise


def get_all_images():
   images = []
   for file in fs.find():
        image_url = url_for('get_image', file_id=str(file._id))
        images.append({'name': file.filename, 'url': image_url})
   return images
