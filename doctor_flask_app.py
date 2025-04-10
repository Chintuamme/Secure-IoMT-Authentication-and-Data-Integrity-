import os
import json
from flask import Flask, render_template, request, redirect, url_for
from pymongo import MongoClient

# Post-quantum library
import oqs
# AES for decryption
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Twilio for sending SMS alerts
from twilio.rest import Client as TwilioClient

# -------------------- CONFIG: MongoDB Atlas --------------------
MONGO_URI = (
    "mongodb+srv://Rocky27:sp191612@iomt.x5hkb.mongodb.net/"
    "?retryWrites=true&w=majority&appName=iomt"
)
client = MongoClient(MONGO_URI)
db = client["IoMT_Project"]
collection = db["sensor_data"]

# -------------------- FILES: Doctor's & Sensor's Keys --------------------
DOCTOR_KYBER_SECRET_KEY_FILE = "doctor_kyber_secret_key.bin"
SENSOR_DILITHIUM_PUBLIC_KEY_FILE = "sensor_dilithium_pub.bin"

# -------------------- Twilio Credentials (Replace with real info) --------------------
TWILIO_ACCOUNT_SID = "AC2e37ad16c20ffabec241754831f6c5bc"  # e.g., "AC123456789abcdef"
TWILIO_AUTH_TOKEN = "91447cabdc41b04ec0a4c2f27319e3f2"     # e.g., "123456789abcdef"
TWILIO_FROM_NUMBER = "+19187312588" # e.g., Twilio-provided phone number
PATIENT_FAMILY_NUMBER = "+917731919212"  # The phone number to send alerts

app = Flask(__name__)

def load_doctor_kyber_secret_key():
    with open(DOCTOR_KYBER_SECRET_KEY_FILE, "rb") as f:
        return f.read()

def load_sensor_dilithium_public_key():
    with open(SENSOR_DILITHIUM_PUBLIC_KEY_FILE, "rb") as f:
        return f.read()

# -------------------- Decrypt & Verify Logic --------------------
def verify_and_decrypt(document, doc_secret_key, sensor_pub_key):
    """
    1) Verify signature (Dilithium).
    2) Decapsulate (Kyber) to get AES key.
    3) Decrypt AES ciphertext to recover sensor data.
    """
    combined_ciphertext = document["combined_ciphertext"]
    signature_hex = document["signature"]
    signature = bytes.fromhex(signature_hex)

    to_verify = json.dumps(combined_ciphertext).encode()

    # 1) Verify with Dilithium
    with oqs.Signature("Dilithium3") as verifier:
        valid = verifier.verify(to_verify, signature, sensor_pub_key)
    if not valid:
        return None  # signature failed

    # 2) Decapsulate (Kyber)
    kem_ciphertext = bytes.fromhex(combined_ciphertext["kem_ciphertext"])
    with oqs.KeyEncapsulation("Kyber512", secret_key=doc_secret_key) as kem:
        shared_secret_doctor = kem.decap_secret(kem_ciphertext)

    # 3) AES decryption
    aes_key = shared_secret_doctor[:32]
    iv = bytes.fromhex(combined_ciphertext["iv"])
    aes_ciphertext = bytes.fromhex(combined_ciphertext["aes_ciphertext"])

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(aes_ciphertext)
    try:
        decrypted_data = unpad(decrypted_padded, AES.block_size)
    except ValueError:
        return None  # error in unpadding

    return json.loads(decrypted_data.decode())

# -------------------- Simple Anomaly Detection --------------------
def check_anomaly(sensor_data):
    anomalies = []
    bp = sensor_data.get("blood_pressure", {})
    systolic = bp.get("systolic", 0)
    diastolic = bp.get("diastolic", 0)

    if systolic > 140 or diastolic > 90:
        anomalies.append("High blood pressure")
    elif systolic < 90 or diastolic < 60:
        anomalies.append("Low blood pressure")

    heart_rate = sensor_data.get("heart_rate", 0)
    if heart_rate > 120:
        anomalies.append("High heart rate")
    elif heart_rate < 50:
        anomalies.append("Low heart rate")

    temperature = sensor_data.get("temperature", 0)
    if temperature > 38.5:
        anomalies.append("Fever (high temperature)")
    elif temperature < 36.0:
        anomalies.append("Low body temperature")

    glucose = sensor_data.get("glucose", 0)
    if glucose > 180:
        anomalies.append("High glucose level")
    elif glucose < 70:
        anomalies.append("Low glucose level")

    return anomalies

# -------------------- Flask Routes --------------------
@app.route("/")
def index():
    """
    Display the most recent sensor data entries in a table,
    along with anomalies and a button to send alerts.
    """
    doc_secret_key = load_doctor_kyber_secret_key()
    sensor_pub_key = load_sensor_dilithium_public_key()

    # Retrieve the latest 5 documents (adjust as needed)
    documents = collection.find().sort("timestamp", -1).limit(5)

    # Decrypt each document and check anomalies
    decrypted_entries = []
    for doc in documents:
        decrypted_data = verify_and_decrypt(doc, doc_secret_key, sensor_pub_key)
        if decrypted_data is None:
            # If signature or decryption fails, skip
            continue

        anomalies = check_anomaly(decrypted_data)
        decrypted_entries.append({
            "doc_id": str(doc["_id"]),
            "sensor_data": decrypted_data,
            "anomalies": anomalies
        })

    return render_template("index.html", entries=decrypted_entries)

@app.route("/send_alert", methods=["POST"])
def send_alert():
    """
    Send an SMS alert to the patient's family using Twilio.
    This route is triggered by a button on the web page.
    """
    # In a real app, you'd parse the doc_id or patient info from the form.
    # For now, we just send a static message.
    try:
        twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        message_body = "ALERT: The doctor has flagged an anomaly in the patient's vitals. Please check immediately."

        message = twilio_client.messages.create(
            body=message_body,
            from_=TWILIO_FROM_NUMBER,
            to=PATIENT_FAMILY_NUMBER
        )
        print("SMS Alert sent:", message.sid)
    except Exception as e:
        print("Error sending SMS:", e)

    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
