"Task 2: Create signature in the end of the file"
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from PIL import Image

IMAGE_PATH = "images/taylor_swift.png"
image = Image.open(IMAGE_PATH)

with open(IMAGE_PATH, "rb") as f:
    image_data = f.read()
    HASH_VALUE = hashlib.sha256(image_data).digest()

with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

signature = private_key.sign(
    HASH_VALUE,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

with open("images/image_signed.png", "wb") as f:
    f.write(image_data)
    f.write(signature)

print("Зображення підписано!")
