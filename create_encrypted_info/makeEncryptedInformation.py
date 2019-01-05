import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def key_generator(word):
    password_provided = word #This is input in the form of a string
    password = password_provided.encode() #Convert to type bytes

    salt = b'\xc5P*\xe0a\xc2\\rr+\x95\x18\x995*\x8c' #CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

username = input("What is your name? ")
password = input("What is your password? ")

username_key = key_generator(username).decode()
password_key = key_generator(password).decode()

print("Paste these into the .encrypted files: ")
print("Encrypted Username: " + username_key)
print("Encrypted Password: " + password_key)

input("Press Enter to Leave: ")
