"Task 3: Create signature in the end of the file"
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

with open("images/image_signed.png", "rb") as f:
    full_data = f.read()

signature = full_data[-512:]
image_data = full_data[:-512]

HASH_VALUE = hashlib.sha256(image_data).digest()

try:
    public_key.verify(
        signature,
        HASH_VALUE,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Підпис правильний :)")
except InvalidSignature:
    print("Підпис неправильний :(")
