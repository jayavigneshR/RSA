import os
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import mimetypes
from os import urandom

app = Flask(__name__)

# Allow file upload of larger sizes (e.g., videos/audio)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB limit for file uploads
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
    aes_key = urandom(32)  # 256-bit AES key
    iv = urandom(16)  # AES initialization vector

    with open(file_path, "rb") as f:
        file_data = f.read()

    # Ensure data is padded to be a multiple of 16 bytes
    pad_length = 16 - len(file_data) % 16
    padded_data = file_data + bytes([pad_length]) * pad_length

    # AES Encryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Encrypt AES key using RSA
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

    # Save encrypted data
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_aes_key)
        f.write(iv)
        f.write(encrypted_data)

    return encrypted_file_path


# Decrypt the file using AES and RSA for the AES key
def decrypt_file(file_path):
    with open(file_path, "rb") as f:
        encrypted_aes_key = f.read(256)  # Encrypted AES key
        iv = f.read(16)  # Initialization Vector
        encrypted_data = f.read()  # Encrypted file content

    # Decrypt AES key
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

    # AES Decryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding safely
    pad_length = decrypted_data[-1]
    if pad_length < 1 or pad_length > 16:
        raise ValueError("Invalid padding detected during decryption.")
    
    decrypted_data = decrypted_data[:-pad_length]

    # Restore original filename
    original_filename = os.path.basename(file_path).replace(".enc", "")
    decrypted_file_path = os.path.join(UPLOAD_FOLDER, original_filename)

    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)

    return decrypted_file_path


@app.route('/encrypt', methods=['POST'])
def encrypt():
    file = request.files['file']
    if not file:
        return "No file uploaded", 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)

    encrypted_file_path = encrypt_file(file_path)
    return send_file(encrypted_file_path, as_attachment=True)


@app.route('/decrypt', methods=['POST'])
def decrypt():
    file = request.files['file']
    if not file:
        return "No file uploaded", 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)

    try:
        decrypted_file_path = decrypt_file(file_path)
        mime_type, _ = mimetypes.guess_type(decrypted_file_path)
        return send_file(decrypted_file_path, as_attachment=True, mimetype=mime_type)
    except Exception as e:
        return f"Decryption failed: {str(e)}", 500


@app.route('/')
def home():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)

