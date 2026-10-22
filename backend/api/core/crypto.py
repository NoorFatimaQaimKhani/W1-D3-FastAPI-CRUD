import base64
import hashlib
import json
import os

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGORITHM = "RSA-OAEP-SHA256+A256GCM"
AAD = b"customer-records:v1"  
MIN_RSA_BITS = 2048


class InvalidPublicKey(ValueError):
    pass


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def load_rsa_public_key(pem: str) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise InvalidPublicKey("Not a valid PEM-encoded public key") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise InvalidPublicKey("Only RSA public keys are supported")
    if key.key_size < MIN_RSA_BITS:
        raise InvalidPublicKey(f"RSA key must be at least {MIN_RSA_BITS} bits")
    return key


def public_key_fingerprint(key: rsa.RSAPublicKey) -> str:
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def encrypt_for_public_key(public_key_pem: str, payload) -> dict:
    public_key = load_rsa_public_key(public_key_pem)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, AAD)
    wrapped_key = public_key.encrypt(aes_key, _oaep())

    return {
        "alg": ALGORITHM,
        "key_fingerprint": public_key_fingerprint(public_key),
        "encrypted_key": _b64(wrapped_key),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }
