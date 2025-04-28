"Task 3: Create signature hidden in metadata"
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from PIL import Image

image = Image.open("images/image_signed_modified.png")

signature_hex = image.text.get("hidden_signature", None)
if not signature_hex:
    print("Підпис не знайдено у зображенні!")
    exit()

signature = bytes.fromhex(signature_hex)

with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

image_bytes = image.tobytes()

digest = hashes.Hash(hashes.SHA256())
digest.update(image_bytes)
hashed = digest.finalize()

try:
    public_key.verify(
        signature,
        hashed,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    print("Підпис правильний :)")
except InvalidSignature:
    print("Підпис неправильний :(")
