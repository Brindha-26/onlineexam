import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import sys

# Ensure UTF-8 output if possible, but we'll use ASCII for safety
def test_decrypt():
    exam_type = "1234"
    aes_key_file = f'encrypted/encrypted_aes_key_{exam_type}.bin'
    encrypted_questions_file = f'encrypted/encrypted_questions_{exam_type}.bin'
    private_key_file = 'private_key.pem'

    print(f"Testing decryption for {exam_type}...")
    
    try:
        if not os.path.exists(private_key_file):
            print(f"ERROR: {private_key_file} not found")
            return
        
        with open(private_key_file, "rb") as f:
            private_key = RSA.import_key(f.read())
        print("OK: Private key loaded")

        if not os.path.exists(aes_key_file):
            print(f"ERROR: {aes_key_file} not found")
            return

        with open(aes_key_file, "rb") as f:
            enc_aes_key = f.read()
        print(f"OK: Encrypted AES key loaded ({len(enc_aes_key)} bytes)")

        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(enc_aes_key)
        print("OK: AES key decrypted with RSA")

        if not os.path.exists(encrypted_questions_file):
            print(f"ERROR: {encrypted_questions_file} not found")
            return

        with open(encrypted_questions_file, "rb") as f:
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()
        print(f"OK: Encrypted questions loaded ({len(ciphertext)} bytes)")

        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        print("OK: Questions decrypted with AES")
        
        questions = json.loads(data)
        print(f"OK: JSON parsed successfully ({len(questions)} questions found)")
        
        for i, q in enumerate(questions[:2]):
            print(f"  Q{i+1}: {q.get('question', 'NO_QUESTION')[:50]}...")

    except Exception as e:
        print(f"FAIL: Decryption FAILED: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_decrypt()
