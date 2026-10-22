
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_DIR = Path("keys")
PRIVATE = KEY_DIR / "jwt_private.pem"
PUBLIC = KEY_DIR / "jwt_public.pem"


def main() -> None:
    if PRIVATE.exists() or PUBLIC.exists():
        raise SystemExit(
            "Key files already exist. Refusing to overwrite them (that would "
            "invalidate every issued token). Delete them first if you really want new keys."
        )

    KEY_DIR.mkdir(exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    PRIVATE.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    PUBLIC.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    try:
        PRIVATE.chmod(0o600) 
    except OSError:
        pass

    print(f"Created {PRIVATE} and {PUBLIC}\n")
    print("Add these two lines to your .env file:")
    print("JWT_PRIVATE_KEY_PATH=keys/jwt_private.pem")
    print("JWT_PUBLIC_KEY_PATH=keys/jwt_public.pem")


if __name__ == "__main__":
    main()