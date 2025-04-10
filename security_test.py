import json
import time
import random
from pymongo import MongoClient
import oqs
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# MongoDB connection
MONGO_URI = "mongodb+srv://Rocky27:sp191612@iomt.x5hkb.mongodb.net/?retryWrites=true&w=majority&appName=iomt"
client = MongoClient(MONGO_URI)
db = client["IoMT_Project2"]  # Database name
collection = db["sensor_data"]  # Collection name

DOCTOR_KYBER_SECRET_KEY_FILE = "doctor_kyber_secret_key.bin"
SENSOR_DILITHIUM_PUBLIC_KEY_FILE = "sensor_dilithium_pub.bin"

# Load the doctor's Kyber private key
def load_doctor_secret_key():
    with open(DOCTOR_KYBER_SECRET_KEY_FILE, "rb") as f:
        return f.read()

# Load the sensor's Dilithium public key
def load_sensor_dilithium_public_key():
    with open(SENSOR_DILITHIUM_PUBLIC_KEY_FILE, "rb") as f:
        return f.read()

# Fetch latest sensor data from MongoDB
def fetch_latest_sensor_data():
    return collection.find_one(sort=[("timestamp", -1)])

# Attempt unauthorized decryption
def unauthorized_decryption(combined_ciphertext):
    try:
        print("\n🚨 Attempting Unauthorized Decryption...")
        fake_private_key = bytes(random.getrandbits(8) for _ in range(64))  # Fake private key
        with oqs.KeyEncapsulation("Kyber512") as kem:
            shared_secret = kem.decap_secret(fake_private_key, bytes.fromhex(combined_ciphertext["kem_ciphertext"]))
        aes_key = shared_secret[:32]
        iv = bytes.fromhex(combined_ciphertext["iv"])
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(bytes.fromhex(combined_ciphertext["aes_ciphertext"])), AES.block_size)
        print("❌ Unauthorized Decryption Succeeded! This is a security flaw!")
    except Exception as e:
        print("✅ Unauthorized Decryption Blocked!", e)

# Attempt data tampering
def tampering_attack(document):
    print("\n🚨 Attempting Data Tampering...")
    document["combined_ciphertext"]["aes_ciphertext"] = "0" * len(document["combined_ciphertext"]["aes_ciphertext"])  # Corrupt data
    try:
        verify_signature(document["combined_ciphertext"], bytes.fromhex(document["signature"]))
    except:
        print("✅ Tampering Detected! Data integrity is maintained.")

# Attempt signature forgery
def signature_forgery(document):
    print("\n🚨 Attempting Signature Forgery...")
    fake_signature = bytes(random.getrandbits(8) for _ in range(3296))  # Fake signature size for Dilithium3
    try:
        verify_signature(document["combined_ciphertext"], fake_signature)
        print("❌ Fake Signature Accepted! This is a security flaw!")
    except:
        print("✅ Fake Signature Rejected! System is secure.")

# Attempt replay attack
def replay_attack(document):
    print("\n🚨 Attempting Replay Attack...")
    document["timestamp"] = time.time() + 500  # Change timestamp
    collection.insert_one(document)  # Insert duplicate data
    print("✅ Replay Attack Successful! Check if the system detects duplicate data.")

# Verify signature
def verify_signature(combined_ciphertext, signature):
    sensor_dilithium_pub = load_sensor_dilithium_public_key()
    with oqs.Signature("Dilithium3", sensor_dilithium_pub) as verifier:
        verifier.verify(json.dumps(combined_ciphertext).encode(), signature)
        print("✅ Signature Verification: Valid")

# Main execution function
def main():
    print("=== IoMT Security Test Running... ===")
    print("🔍 Fetching latest encrypted sensor data from MongoDB...")
    
    document = fetch_latest_sensor_data()
    if not document:
        print("❌ No data found. Please run the sensor simulation first.")
        return
    
    print("✅ Data Retrieved. Attempting Attacks...")
    unauthorized_decryption(document["combined_ciphertext"])
    tampering_attack(document)
    signature_forgery(document)
    replay_attack(document)

if __name__ == "__main__":
    main()
