import json
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Step 1: Generate RSA key pair (only once)
if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key)
    with open("public_key.pem", "wb") as f:
        f.write(public_key)

# Step 2: Load public key
recipient_key = RSA.import_key(open("public_key.pem").read())
cipher_rsa = PKCS1_OAEP.new(recipient_key)

# Step 3: Encrypt each subject’s JSON file
subjects = ["python", "network", "ai", "cyber", "ds"]  # modify as needed

for subject in subjects:
    input_file = f"{subject}_questions.json"
    if not os.path.exists(input_file):
        print(f"❌ File not found: {input_file}")
        continue

    with open(input_file, "r", encoding='utf-8') as f:
        questions = json.load(f)

    data = json.dumps(questions).encode()
    aes_key = get_random_bytes(16)

    # AES encryption
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    # Write encrypted question file
    with open(f"encrypted_questions_{subject}.bin", "wb") as f:
        [f.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]

    # Encrypt AES key with RSA
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    with open(f"encrypted_aes_key_{subject}.bin", "wb") as f:
        f.write(enc_aes_key)

    print("Encryption complete. Files generated:")
    print("- private_key.pem")
    print("- public_key.pem")
    print("- encrypted_aes_key.bin")
    print("- encrypted_questions.bin")
