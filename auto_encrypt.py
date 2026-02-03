import json
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "adminpanel" / "uploads"
ENCRYPTED_DIR = BASE_DIR / "encrypted"
PUBLIC_KEY_PATH = BASE_DIR / "public_key.pem"
PRIVATE_KEY_PATH = BASE_DIR / "private_key.pem"

def ensure_keys():
    """Generates RSA keys if they don't exist."""
    if not PUBLIC_KEY_PATH.exists() or not PRIVATE_KEY_PATH.exists():
        print("Generating new RSA key pair...")
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key)
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key)
        print("Keys generated.")

def encrypt_files():
    """Scans UPLOAD_DIR for JSON files and encrypts them into ENCRYPTED_DIR."""
    ensure_keys()
    
    if not UPLOAD_DIR.exists():
        print(f"Upload directory not found: {UPLOAD_DIR}")
        return

    os.makedirs(ENCRYPTED_DIR, exist_ok=True)
    
    # Load public key
    recipient_key = RSA.import_key(open(PUBLIC_KEY_PATH).read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    
    json_files = list(UPLOAD_DIR.glob("*.json"))
    
    if not json_files:
        print("No JSON files found in uploads.")
        return
    
    for input_file in json_files:
        subject = input_file.stem
        print(f"Processing: {input_file.name} (Subject: {subject})")
        
        try:
            with open(input_file, "r", encoding='utf-8') as f:
                questions = json.load(f)
            
            data = json.dumps(questions).encode('utf-8')
            aes_key = get_random_bytes(16)
            
            # AES encryption (EAX mode for built-in authentication)
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data)
            
            # Write encrypted question file
            # Format: nonce + tag + ciphertext (matches decrypt_and_load_questions.py)
            questions_out = ENCRYPTED_DIR / f"encrypted_questions_{subject}.bin"
            with open(questions_out, "wb") as f:
                [f.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]
            
            # Encrypt AES key with RSA
            enc_aes_key = cipher_rsa.encrypt(aes_key)
            key_out = ENCRYPTED_DIR / f"encrypted_aes_key_{subject}.bin"
            with open(key_out, "wb") as f:
                f.write(enc_aes_key)
                
            print(f"Successfully encrypted {subject}")
            
        except Exception as e:
            print(f"Error processing {input_file.name}: {e}")

if __name__ == "__main__":
    encrypt_files()
