# mongo_storage.py
from pymongo import MongoClient
from datetime import datetime

class KeyStorage:
    def __init__(self, uri):
        self.client = MongoClient(uri)
        self.db = self.client.secure_chat
        self.dh_keys = self.db.dh_keys

    def store_dh_private_key(self, participant_name, key_info):
        """Store the DH private key and related parameters"""
        document = {
            'participant': participant_name,
            'dh_private_key': key_info['private_key'],  # The secret exponent
            'dh_public_key': key_info['public_key'],    # The calculated public value
            'base': key_info['base'],
            'modulus': key_info['modulus'],
            'timestamp': datetime.utcnow()
        }
        return self.dh_keys.insert_one(document)

    def get_latest_dh_key(self, participant_name):
        """Retrieve the latest DH key for a participant"""
        return self.dh_keys.find_one(
            {'participant': participant_name},
            sort=[('timestamp', -1)]
        )

    def close(self):
        """Close the MongoDB connection"""
        self.client.close()