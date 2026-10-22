from pydantic import BaseModel


class EncryptedEnvelope(BaseModel):

    alg: str
    key_fingerprint: str
    encrypted_key: str
    nonce: str
    ciphertext: str
