from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from secrets import token_bytes
import hashlib


def key_generator():
    return token_bytes(8)

def encrypt(message, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode('ascii'), DES.block_size)) # Adds padding and encrypt message using CBC mode
    return ciphertext, cipher.iv

def decrypt(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size) # Removes padding and decrypt message using CBC mode
    return plaintext.decode('ascii')

def hash_message(message):
    return hashlib.sha256(message.encode('ascii')).hexdigest()

def integrity_check(message, hash_value):
    return hash_message(message) == hash_value # Checks the integrity of the decrypted message

