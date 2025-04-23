import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Шляхи до ключів (змінюй при потребі)
PRIVATE_KEY_PATH = "./rsa_private.pem"
PUBLIC_KEY_PATH = "./rsa_public.pem"


def generate_rsa_keys():
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        print("✅ Ключі вже існують. Генерація не потрібна.")
        return

    print("🔐 Генеруємо нову пару RSA-ключів...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("✅ Ключі успішно згенеровано та збережено!")


if __name__ == "__main__":
    generate_rsa_keys()
