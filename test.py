#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import os
import json


def pad(s):
    for i in range(0, 32 - (len(s) % 32)):
        s += " "
    return s


backend = default_backend()

key1 = os.urandom(32)
iv1 = os.urandom(16)
key2 = os.urandom(32)
iv2 = os.urandom(16)

message = input("MESSAGE BITCH:")
print(f"Len of message: {len(message)}")
# Pad the mesasge to the next 32 character length
message = pad(message)

print(f"Post Padding len of message: {len(message)}")
print(f"message: '{message}'")

cipher = Cipher(algorithms.AES(key1), modes.CBC(iv1), backend=backend)
encryptor = cipher.encryptor()

ct = encryptor.update(message.encode()) + encryptor.finalize()

rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = rsa_priv.public_key()

wrap = {
    "message": base64.b64encode(ct).decode(),
    "key": base64.b64encode(
        pub.encrypt(
            key1 + iv1,
            padding.OAEP(
                padding.MGF1(algorithm=hashes.SHA256()), hashes.SHA256(), label=None
            ),
        )
    ).decode(),
}
wrap_s = pad(json.dumps(wrap))

cipher = Cipher(algorithms.AES(key2), modes.CBC(iv2), backend=backend)
encryptor = cipher.encryptor()

eline = encryptor.update(wrap_s.encode()) + encryptor.finalize()
eline = base64.b64encode(eline)

print(f" eline: '{eline}'")

eline = base64.b64decode(eline)
decryptor = cipher.decryptor()
foobar = decryptor.update(eline) + decryptor.finalize()

print(foobar)
dewrap = json.loads(foobar.decode())

key = base64.b64decode(dewrap["key"])
dekey = rsa_priv.decrypt(
    key,
    padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()), hashes.SHA256(), label=None),
)

aes_key1 = dekey[0:32]
print(f"key: {aes_key1 }")
aes_iv1 = dekey[32:48]
cipher = Cipher(algorithms.AES(aes_key1), modes.CBC(aes_iv1), backend=backend)
decryptor = cipher.decryptor()
FUCKING_FINALLY = (
    decryptor.update(base64.b64decode(dewrap["message"])) + decryptor.finalize()
)
print(FUCKING_FINALLY)
