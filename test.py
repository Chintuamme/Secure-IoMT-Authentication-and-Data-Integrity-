from pymongo import MongoClient

MONGO_URI = "mongodb+srv://<username>:<password>@iomt.x5hkb.mongodb.net/?retryWrites=true&w=majority"

client = MongoClient(MONGO_URI)
print(client.list_database_names())
