
import bcrypt


def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt with a random salt."""
    if not password:
        raise ValueError("Password must not be empty.")

    password_bytes = password.encode("utf-8")

    # bcrypt processes at most 72 password bytes.
    if len(password_bytes) > 72:
        raise ValueError(
            "Password exceeds bcrypt's 72-byte limit. "
            "Use a documented pre-hashing design or a "
            "password hashing algorithm with a suitable limit."
        )

    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password_bytes, salt)


def verify_password(password: str, stored_hash: bytes) -> bool:
    """Check a password against its stored bcrypt hash."""
    password_bytes = password.encode("utf-8")

    if len(password_bytes) > 72:
        return False

    try:
        return bcrypt.checkpw(password_bytes, stored_hash)
    except (ValueError, TypeError):
        return False


if __name__ == "__main__":
    password = "Demo-Password-123!"

    stored_hash = hash_password(password)

    print("Stored password hash:", stored_hash.decode("utf-8"))
    print("Correct password:", verify_password(password, stored_hash))
    print("Wrong password:", verify_password("wrong-password", stored_hash))
    print(
        "New hash differs due to random salt:",
        stored_hash != hash_password(password)
    )
