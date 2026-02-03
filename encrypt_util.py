from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os

# Directories
RSA_DIR = "rsa_keys"
ENC_DIR = "encrypted_questions"
os.makedirs(RSA_DIR, exist_ok=True)
os.makedirs(ENC_DIR, exist_ok=True)

# Step 1: Generate RSA Keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(os.path.join(RSA_DIR, 'private.pem'), 'wb') as f:
        f.write(private_key)
    with open(os.path.join(RSA_DIR, 'public.pem'), 'wb') as f:
        f.write(public_key)
    print("RSA keys generated and saved.")

# Step 2: Encrypt Question File with AES
def encrypt_question_file(input_file_path):
    # Load RSA public key
    with open(os.path.join(RSA_DIR, 'public.pem'), 'rb') as f:
        public_key = RSA.import_key(f.read())

    # Generate AES key and IV
    aes_key = get_random_bytes(16)  # AES-128
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)

    # Read and encrypt file
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    # Save encrypted file
    with open(os.path.join(ENC_DIR, 'questions_encrypted.txt'), 'wb') as f:
        [f.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]

    # Encrypt AES key with RSA public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    # Save encrypted AES key
    with open(os.path.join(ENC_DIR, 'encrypted_aes_key.bin'), 'wb') as f:
        f.write(encrypted_key)

    print("Question file encrypted and AES key stored securely.")

# Usage Example:
# generate_rsa_keys()
# encrypt_question_file('questions.txt')
