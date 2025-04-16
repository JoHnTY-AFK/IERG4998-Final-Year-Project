from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted

def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted_data

def encrypt_watermark(watermark, key):
    return aes_encrypt(watermark, key)

def decrypt_watermark(encrypted_watermark, derived_key):
    return aes_decrypt(encrypted_watermark, derived_key)

def encrypt_long_message(message, derived_key):
    encrypted_chunks = []
    message_bytes = message.encode()
    encrypted_message = aes_encrypt(message_bytes, derived_key)
    encrypted_chunks.append(encrypted_message)
    return encrypted_chunks

def decrypt_message(encrypted_data, derived_key):
    decrypted_chunk = aes_decrypt(encrypted_data, derived_key)
    return decrypted_chunk.decode('latin-1')

def encrypt_photo(photo_path, derived_key):
    with open(photo_path, "rb") as photo_file:
        photo_data = photo_file.read()
    encrypted_chunks = []
    encrypted_photo = aes_encrypt(photo_data, derived_key)
    encrypted_chunks.append(encrypted_photo)
    return encrypted_chunks

def decrypt_photo(encrypted_data, derived_key):
    return aes_decrypt(encrypted_data, derived_key)