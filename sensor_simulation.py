import os
import random
import time
import json
from pymongo import MongoClient

# Post-quantum crypto (Kyber for KEM, Dilithium for signatures)
import oqs

# Symmetric encryption (AES) for bulk data
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

#MongoDB connection
MONGO_URI = (
    "mongodb+srv://Rocky27:sp191612@iomt.x5hkb.mongodb.net/"
    "?retryWrites=true&w=majority&appName=iomt"
)
client = MongoClient(MONGO_URI)

db = client["IoMT_Project"]       # Database name
collection = db["sensor_data"]    # Collection name

DOCTOR_KYBER_PUBLIC_KEY_FILE = "doctor_kyber_public_key.bin"
SENSOR_DILITHIUM_PUBLIC_KEY_FILE = "sensor_dilithium_pub.bin"
SENSOR_DILITHIUM_SECRET_KEY_FILE = "sensor_dilithium_sec.bin"

def load_doctor_public_key():
    with open(DOCTOR_KYBER_PUBLIC_KEY_FILE, "rb") as f:
        return f.read()

def load_or_generate_sensor_dilithium_keys():
    if not (
        os.path.exists(SENSOR_DILITHIUM_PUBLIC_KEY_FILE)
        and os.path.exists(SENSOR_DILITHIUM_SECRET_KEY_FILE)
    ):
        with oqs.Signature("Dilithium3") as signer:
            pub_key = signer.generate_keypair()
            sec_key = signer.export_secret_key()
        with open(SENSOR_DILITHIUM_PUBLIC_KEY_FILE, "wb") as f:
            f.write(pub_key)
        with open(SENSOR_DILITHIUM_SECRET_KEY_FILE, "wb") as f:
            f.write(sec_key)

    with open(SENSOR_DILITHIUM_PUBLIC_KEY_FILE, "rb") as f:
        pub_key = f.read()
    with open(SENSOR_DILITHIUM_SECRET_KEY_FILE, "rb") as f:
        sec_key = f.read()
    return pub_key, sec_key

def simulate_sensor_data():
    return {
        "blood_pressure": {
            "systolic": random.randint(90, 140),
            "diastolic": random.randint(60, 90)
        },
        "heart_rate": random.randint(60, 120),
        "temperature": round(random.uniform(36.0, 39.0), 1),
        "glucose": random.randint(70, 180)
    }

def encrypt_and_sign(sensor_data, doctor_pub_key, sensor_dilithium_sec):
    data_bytes = json.dumps(sensor_data).encode()
    with oqs.KeyEncapsulation("Kyber512") as kem:
        ciphertext_kem, shared_secret = kem.encap_secret(doctor_pub_key)

    aes_key = shared_secret[:32]
    iv = b"0123456789abcdef"
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data_bytes, AES.block_size))

    combined_ciphertext = {
        "kem_ciphertext": ciphertext_kem.hex(),
        "aes_ciphertext": encrypted_data.hex(),
        "iv": iv.hex()
    }

    to_sign = json.dumps(combined_ciphertext).encode()
    with oqs.Signature("Dilithium3", secret_key=sensor_dilithium_sec) as signer:
        signature = signer.sign(to_sign)

    return combined_ciphertext, signature

def main():
    doc_pub_key = load_doctor_public_key()
    sensor_dilithium_pub, sensor_dilithium_sec = load_or_generate_sensor_dilithium_keys()

    print("=== Sensor Simulator Started ===")
    print("Loaded doctor's Kyber public key & sensor's Dilithium keys.\n")

    while True:
        data = simulate_sensor_data()
        combined_ciphertext, signature = encrypt_and_sign(data, doc_pub_key, sensor_dilithium_sec)

        document = {
            "plaintext_demo": data,
            "combined_ciphertext": combined_ciphertext,
            "signature": signature.hex(),
            "timestamp": time.time()
        }

        collection.insert_one(document)
        print("Inserted document into MongoDB Atlas:")
        print(document)
        print("Waiting 10 seconds before next data simulation...\n")
        time.sleep(10)

if __name__ == "__main__":
    main()
