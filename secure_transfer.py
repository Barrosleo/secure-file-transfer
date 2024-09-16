import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import socket

# Encryption and Decryption Functions
def encrypt_file(file_path, password):
    backend = default_backend()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    with open(file_path, 'rb') as f:
        data = f.read()

    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + iv + encrypted_data)

def decrypt_file(file_path, password):
    backend = default_backend()
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    with open(file_path[:-4], 'wb') as f:
        f.write(unpadded_data)

# Functions for Sending and Receiving Files
def send_file(file_path, host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        with open(file_path, 'rb') as f:
            s.sendall(f.read())

def receive_file(file_path, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', port))
        s.listen()
        conn, addr = s.accept()
        with conn:
            with open(file_path, 'wb') as f:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    f.write(data)

# Main Function to Run the Tool
if __name__ == "__main__":
    choice = input("Do you want to (e)ncrypt, (d)ecrypt, (s)end, or (r)eceive a file? ")

    if choice == 'e':
        file_path = input("Enter the file path to encrypt: ")
        password = input("Enter the password: ")
        encrypt_file(file_path, password)
        print("File encrypted successfully.")

    elif choice == 'd':
        file_path = input("Enter the file path to decrypt: ")
        password = input("Enter the password: ")
        decrypt_file(file_path, password)
        print("File decrypted successfully.")

    elif choice == 's':
        file_path = input("Enter the file path to send: ")
        host = input("Enter the host to send to: ")
        port = int(input("Enter the port: "))
        send_file(file_path, host, port)
        print("File sent successfully.")

    elif choice == 'r':
        file_path = input("Enter the file path to save received file: ")
        port = int(input("Enter the port: "))
        receive_file(file_path, port)
        print("File received successfully.")
