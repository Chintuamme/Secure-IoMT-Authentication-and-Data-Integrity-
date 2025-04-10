import oqs
import random

def generate_signature(secret_key, message):
    """Signs the message using Dilithium3."""
    with oqs.Signature("Dilithium3", secret_key=secret_key) as signer:
        return signer.sign(message)

def verify_signature(public_key, message, signature):
    """Verifies the Dilithium3 signature."""
    with oqs.Signature("Dilithium3") as verifier:
        return verifier.verify(message, signature, public_key)

def simulate_authentication_tests(total_tests=1000, failure_rate=0.013):
    """Simulates multiple authentication attempts and calculates success rate."""
    
    # Generate a key pair for Dilithium3
    with oqs.Signature("Dilithium3") as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    successful_authentications = 0

    for _ in range(total_tests):
        message = b"Test IoMT Authentication"

        # 1. Simulate a valid signature
        signature = generate_signature(secret_key, message)

        # 2. Introduce some authentication failures
        if random.random() < failure_rate:
            # Corrupt the signature to simulate failure
            signature = signature[:-1] + b'\x00'

        # 3. Verify signature
        if verify_signature(public_key, message, signature):
            successful_authentications += 1

    # Calculate success rate
    success_rate = (successful_authentications / total_tests) * 100
    print(f"Total Authentication Attempts: {total_tests}")
    print(f"Successful Authentications: {successful_authentications}")
    print(f"Authentication Success Rate: {success_rate:.2f}%")

# Run the simulation
simulate_authentication_tests(total_tests=1000)
