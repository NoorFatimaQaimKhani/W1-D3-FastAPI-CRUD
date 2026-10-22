from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.models.customer import Customer


def get(db: Session, customer_id: int) -> Customer | None:
    return db.get(Customer, customer_id)


def list_all(db: Session, limit: int, offset: int) -> list[Customer]:
    stmt = select(Customer).order_by(Customer.id).limit(limit).offset(offset)
    return list(db.scalars(stmt))


def list_for_owner(db: Session, owner_id: int, limit: int, offset: int) -> list[Customer]:
    stmt = (
        select(Customer)
        .where(Customer.owner_id == owner_id)
        .order_by(Customer.id)
        .limit(limit)
        .offset(offset)
    )
    return list(db.scalars(stmt))


def count_by_owner(db: Session, owner_id: int) -> int:
    return db.scalar(
        select(func.count()).select_from(Customer).where(Customer.owner_id == owner_id)
    )


def add(db: Session, customer: Customer) -> Customer:
    db.add(customer)
    db.flush()
    return customer


def delete(db: Session, customer: Customer) -> None:
    db.delete(customer)
