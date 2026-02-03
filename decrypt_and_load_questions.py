import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

def decrypt_exam_file(encrypted_key_path, encrypted_data_path, private_key_path):
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    with open(encrypted_key_path, "rb") as f:
        enc_aes_key = f.read()

    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    with open(encrypted_data_path, "rb") as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    questions = json.loads(data)

    return questions
