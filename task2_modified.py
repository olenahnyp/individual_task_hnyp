"Task 2: Create signature hidden in metadata"
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from PIL import Image, PngImagePlugin

image = Image.open("taylor_swift.png")

image_bytes = image.tobytes()

with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

digest = hashes.Hash(hashes.SHA256())
digest.update(image_bytes)
hashed = digest.finalize()

signature = private_key.sign(
    hashed,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ),
    hashes.SHA256(),
)

metadata = PngImagePlugin.PngInfo()
metadata.add_text("hidden_signature", signature.hex())

image.save("image_signed_modified.png", pnginfo=metadata)
print("Зображення підписано та збережено як image_signed_modified.png")
