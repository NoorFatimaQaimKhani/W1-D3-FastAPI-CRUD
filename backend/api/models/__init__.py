# Importing every model here guarantees they are registered on Base.metadata
# (Alembic and the tests both rely on that).
from backend.api.models.customer import Customer
from backend.api.models.user import User

__all__ = ["Customer", "User"]