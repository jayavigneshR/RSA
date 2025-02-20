import os
from flask import Flask, render_template, request, send_file
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from os import urandom

app = Flask(__name__)

# Allow file upload of larger sizes (e.g., videos/audio)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB limit for file uploads

# Ensure 'uploads' directory exists
os.makedirs("uploads", exist_ok=True)

# Generate RSA Keys (Run this once to create key files)
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

if not os.path.exists("private_key.pem"):
    generate_keys()


# Encrypt the file using AES and RSA for the AES key
def encrypt_file(file_path):
    # Generate a random AES key
    aes_key = urandom(32)  # 256-bit AES key
    iv = urandom(16)  # AES initialization vector

    # Read the file to encrypt
    with open(file_path, "rb") as f:
        file_data = f.read()

    # Encrypt file data using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Make sure the data is padded to be a multiple of 16 (AES block size)
    pad_length = 16 - len(file_data) % 16
    padded_data = file_data + bytes([pad_length]) * pad_length

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Encrypt the AES key using RSA
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save the encrypted AES key, IV, and encrypted file data
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_aes_key)
        f.write(iv)
        f.write(encrypted_data)

    return encrypted_file_path


# Decrypt the file using AES and RSA for the AES key
def decrypt_file(file_path):
    # Read the encrypted file
    with open(file_path, "rb") as f:
        encrypted_aes_key = f.read(256)  # RSA-encrypted AES key (2048-bit RSA key)
        iv = f.read(16)  # IV used for AES encryption
        encrypted_data = f.read()  # Encrypted file data

    # Decrypt the AES key using RSA
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the file data using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    pad_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-pad_length]

    # Get the original file extension from the encrypted file
    original_extension = file_path.split('.')[-1] if '.' in file_path else 'bin'
    
    decrypted_file_path = file_path.replace(".enc", f".{original_extension}")
    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)

    return decrypted_file_path


@app.route('/encrypt', methods=['POST'])
def encrypt():
    file = request.files['file']
    file_path = os.path.join("uploads", file.filename)
    file.save(file_path)

    encrypted_file_path = encrypt_file(file_path)
    return send_file(encrypted_file_path, as_attachment=True)


@app.route('/decrypt', methods=['POST'])
def decrypt():
    file = request.files['file']
    file_path = os.path.join("uploads", file.filename)
    file.save(file_path)

    decrypted_file_path = decrypt_file(file_path)
    return send_file(decrypted_file_path, as_attachment=True)


@app.route('/')
def home():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
