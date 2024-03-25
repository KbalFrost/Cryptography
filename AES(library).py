# Import the required modules
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import codecs


# Define the encryption function
def encrypt_AES_CBC_256(key, message):
    key_bytes = codecs.encode(key, 'utf-8')
    message_bytes = codecs.encode(message, 'utf-8')
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    padded_message = pad(message_bytes, AES.block_size)
    ciphertext_bytes = cipher.encrypt(padded_message)
    ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
    return ciphertext

# Define the decryption function
def decrypt_AES_CBC_256(key, ciphertext):
    key_bytes = codecs.encode(key, 'utf-8')
    ciphertext_bytes = b64decode(ciphertext)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(ciphertext_bytes)
    plaintext_bytes = unpad(decrypted_bytes, AES.block_size)
    plaintext = plaintext_bytes.decode('utf-8')
    return plaintext

# Set the 256-bit key and plaintext message
key = 'ThisIsASecretKey'
message = 'Welcome to Fundamental of Cryptography'

# Encrypt the message
encrypted_message = encrypt_AES_CBC_256(key, message)

# Decrypt the message
decrypted_message = decrypt_AES_CBC_256(key, encrypted_message)

# Print the original and decrypted messages
print('Original Message:', message)
print(type(message))
print('Encrypted Message:', encrypted_message)
print(type(encrypted_message))
print('Decrypted Message:', decrypted_message)
print(type(decrypted_message))