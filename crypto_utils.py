
import os
import base64
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_message(message: str, key: bytes) -> dict:
    """Encrypt UTF-8 text using AES-256-GCM."""
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    # GCM uses a fresh, unpredictable 12-byte nonce (IV).
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_message(encrypted: dict, key: bytes) -> str:
    """Decrypt and authenticate AES-GCM ciphertext."""
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = base64.b64decode(encrypted["nonce"], validate=True)
    ciphertext = base64.b64decode(
        encrypted["ciphertext"], validate=True
    )

    if len(nonce) != 12:
        raise ValueError("Invalid GCM nonce length.")

    plaintext = AESGCM(key).decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")


def create_hmac(message: str, secret: bytes) -> str:
    """Create an HMAC-SHA256 authentication tag."""
    return hmac.new(
        secret,
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_hmac(message: str, secret: bytes, tag: str) -> bool:
    """Verify an HMAC using constant-time comparison."""
    expected = create_hmac(message, secret)
    return hmac.compare_digest(expected, tag)


if __name__ == "__main__":
    # Demonstration keys only. Use a secrets manager in production.
    aes_key = AESGCM.generate_key(bit_length=256)
    hmac_key = os.urandom(32)

    message = "This is my confidential message."

    encrypted = encrypt_message(message, aes_key)
    print("Encrypted payload:", encrypted)

    decrypted = decrypt_message(encrypted, aes_key)
    print("Decrypted message:", decrypted)

    tag = create_hmac(message, hmac_key)
    print("HMAC:", tag)
    print("HMAC valid:", verify_hmac(message, hmac_key, tag))

    print(
        "Tampered message valid:",
        verify_hmac(message + " changed", hmac_key, tag)
    )
