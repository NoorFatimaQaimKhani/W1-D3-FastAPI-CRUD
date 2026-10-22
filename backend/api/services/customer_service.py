from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.api.core.permissions import (
    can_modify_customer,
    can_view_all_customers,
    can_view_customer,
)
from backend.api.db.connection import commit
from backend.api.models.customer import Customer
from backend.api.models.user import User
from backend.api.repositories import customer_repository
from backend.api.schemas.customer import CustomerCreate, CustomerUpdate


def _get_authorized(db: Session, user: User, customer_id: int, *, modify: bool) -> Customer:
    customer = customer_repository.get(db, customer_id)
    if customer is None or not can_view_customer(user, customer):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Customer not found")
    if modify and not can_modify_customer(user, customer):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You may only modify your own records")
    return customer


def create_customer(db: Session, user: User, data: CustomerCreate) -> Customer:
    customer = Customer(owner_id=user.id, **data.model_dump())
    customer_repository.add(db, customer)
    commit(db)
    db.refresh(customer)
    return customer


def list_customers(db: Session, user: User, limit: int, offset: int) -> list[Customer]:
    if can_view_all_customers(user):
        return customer_repository.list_all(db, limit, offset)
    return customer_repository.list_for_owner(db, user.id, limit, offset)


def get_customer(db: Session, user: User, customer_id: int) -> Customer:
    return _get_authorized(db, user, customer_id, modify=False)


def update_customer(
    db: Session, user: User, customer_id: int, data: CustomerUpdate
) -> Customer:
    customer = _get_authorized(db, user, customer_id, modify=True)
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(customer, field, value)
    commit(db)
    db.refresh(customer)
    return customer


def delete_customer(db: Session, user: User, customer_id: int) -> None:
    customer = _get_authorized(db, user, customer_id, modify=True)
    customer_repository.delete(db, customer)
    commit(db)
