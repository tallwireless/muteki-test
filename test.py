#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

backend = default_backend()

key = os.urandom(32)
iv = os.urandom(16)

message = input("MESSAGE BITCH:")
print(f"Len of message: {len(message)}")
# Pad the mesasge to the next 32 character length
for i in range(0, 32 - (len(message) % 32)):
    message += " "

print(f"Post Padding len of message: {len(message)}")
print(f"message: '{message}'")

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

encryptor = cipher.encryptor()

ct = encryptor.update(message.encode()) + encryptor.finalize()

print(ct)

decryptor = cipher.decryptor()
foobar = decryptor.update(ct) + decryptor.finalize()

print(foobar)
