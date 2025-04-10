import oqs

def main():
    # Choose your Kyber variant, e.g., Kyber512
    with oqs.KeyEncapsulation("Kyber512") as kem:
        pub_key = kem.generate_keypair()
        sec_key = kem.export_secret_key()

    # Save the public and secret keys to files
    with open("doctor_kyber_public_key.bin", "wb") as f:
        f.write(pub_key)
    with open("doctor_kyber_secret_key.bin", "wb") as f:
        f.write(sec_key)

    print("Doctor's Kyber key pair generated and saved.")

if __name__ == "__main__":
    main()
