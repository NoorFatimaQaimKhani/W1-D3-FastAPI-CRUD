from enum import Enum


class Role(str, Enum):
    USER = "USER"
    MANAGER = "MANAGER"
    ADMIN = "ADMIN"


def can_view_customer(user, customer) -> bool:
    return user.role in (Role.MANAGER.value, Role.ADMIN.value) or customer.owner_id == user.id


def can_modify_customer(user, customer) -> bool:
    return user.role == Role.ADMIN.value or customer.owner_id == user.id


def can_view_all_customers(user) -> bool:
    return user.role in (Role.MANAGER.value, Role.ADMIN.value)
