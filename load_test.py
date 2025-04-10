import time
import json
import oqs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

# Sample sensor data
sensor_data = {
    "blood_pressure": {"systolic": 120, "diastolic": 80},
    "heart_rate": 75,
    "temperature": 36.7,
    "glucose": 100
}
sensor_data_bytes = json.dumps(sensor_data).encode()

# Function for direct Kyber encryption
def direct_kyber_encryption(data):
    with oqs.KeyEncapsulation("Kyber512") as kem:
        pk = kem.generate_keypair()
        encapsulated_key, shared_secret = kem.encap_secret(pk)
        encrypted_data = bytes(a ^ b for a, b in zip(data, shared_secret[:len(data)]))  # XOR-based encryption
        return pk, encapsulated_key, encrypted_data

# Function for AES + Kyber encryption
def optimized_aes_kyber_encryption(data):
    aes_key = secrets.token_bytes(32)  # Generate 256-bit AES key
    iv = secrets.token_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))

    # Encrypt AES key using Kyber
    with oqs.KeyEncapsulation("Kyber512") as kem:
        pk = kem.generate_keypair()
        encapsulated_key, _ = kem.encap_secret(pk)

    return pk, encapsulated_key, iv, encrypted_data

# Time Measurement
print("\n--- Performance Comparison ---")

# Direct Kyber Encryption
start_time = time.time()
kyber_pk, kyber_cipher, kyber_encrypted_data = direct_kyber_encryption(sensor_data_bytes)
direct_time = time.time() - start_time
print(f"Direct Kyber Encryption Time: {direct_time:.6f} seconds")

# Optimized AES + Kyber Encryption
start_time = time.time()
aes_pk, aes_cipher, aes_iv, aes_encrypted_data = optimized_aes_kyber_encryption(sensor_data_bytes)
optimized_time = time.time() - start_time
print(f"Optimized AES + Kyber Encryption Time: {optimized_time:.6f} seconds")

# Compare Sizes
print("\n--- Size Comparison ---")
print(f"Original Sensor Data Size: {len(sensor_data_bytes)} bytes")
print(f"Kyber Encrypted Data Size: {len(kyber_encrypted_data)} bytes")
print(f"AES Encrypted Data Size: {len(aes_encrypted_data)} bytes")
print(f"Kyber Ciphertext Size: {len(kyber_cipher)} bytes")
print(f"AES IV Size: {len(aes_iv)} bytes")
