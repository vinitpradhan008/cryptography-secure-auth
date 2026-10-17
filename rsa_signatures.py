
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


KEY_DIR = Path("keys")
PRIVATE_KEY_FILE = KEY_DIR / "private_key.pem"
PUBLIC_KEY_FILE = KEY_DIR / "public_key.pem"


def generate_keys(password: bytes):
    """Generate RSA-2048 keys and save them to disk."""
    KEY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    encrypted_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password
        )
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # "xb" prevents accidental overwriting of existing key files.
    with PRIVATE_KEY_FILE.open("xb") as file:
        file.write(encrypted_private_pem)
    try:
        with PUBLIC_KEY_FILE.open("xb") as file:
            file.write(public_pem)
    except Exception:
        PRIVATE_KEY_FILE.unlink(missing_ok=True)
        raise

    if os.name != "nt":
        os.chmod(PRIVATE_KEY_FILE, 0o600)

    print("RSA-2048 key pair generated.")


def sign_message(message: bytes, password: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_FILE.read_bytes(),
        password=password
    )

    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(message: bytes, signature: bytes) -> bool:
    public_key = serialization.load_pem_public_key(
        PUBLIC_KEY_FILE.read_bytes()
    )

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


if __name__ == "__main__":
    password_text = os.environ.get("RSA_KEY_PASSWORD")
    if not password_text or len(password_text) < 16:
        raise SystemExit(
            "Set RSA_KEY_PASSWORD to a strong password of "
            "at least 16 characters."
        )

    password = password_text.encode("utf-8")
    message = b"Verify the authenticity of this message."

    if not PRIVATE_KEY_FILE.exists() and not PUBLIC_KEY_FILE.exists():
        generate_keys(password)
    elif not PRIVATE_KEY_FILE.exists() or not PUBLIC_KEY_FILE.exists():
        raise SystemExit("Incomplete key pair. Restore or rotate keys safely.")

    signature = sign_message(message, password)
    print("Signature valid:", verify_signature(message, signature))
    print(
        "Modified message valid:",
        verify_signature(message + b" modified", signature)
    )
