from fastapi.encoders import jsonable_encoder

from backend.api.core.crypto import encrypt_for_public_key
from backend.api.models.user import User


def seal(user: User, data) -> dict:
    return encrypt_for_public_key(user.public_key_pem, jsonable_encoder(data))
