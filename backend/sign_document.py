import hashlib
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

# Document to sign
FILE_PATH = "uploads/student_marks.docx"


# Generate SHA-512 hash
def generate_sha512(file_path):
    sha512 = hashlib.sha512()

    with open(file_path, "rb") as file:
        while True:
            data = file.read(4096)

            if not data:
                break

            sha512.update(data)

    return sha512.digest()


# Load RSA private key
with open("keys/private_key.pem", "rb") as private_file:
    private_key = serialization.load_pem_private_key(
        private_file.read(),
        password=None
    )


# Generate document hash
document_hash = generate_sha512(FILE_PATH)


# Create digital signature
signature = private_key.sign(
    document_hash,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA512()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    Prehashed(hashes.SHA512())
)


# Convert signature to Base64
signature_base64 = base64.b64encode(signature).decode("utf-8")


# Display results
print("✅ Digital signature created successfully!")
print()
print("SHA-512 Hash:")
print(document_hash.hex())
print()
print("Digital Signature:")
print(signature_base64)