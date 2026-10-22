from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session

from backend.api.core.deps import get_current_user, get_user_with_public_key
from backend.api.db.connection import get_db
from backend.api.models.user import User
from backend.api.schemas.crypto import EncryptedEnvelope
from backend.api.schemas.customer import (
    CustomerCreate,
    CustomerList,
    CustomerOut,
    CustomerUpdate,
)
from backend.api.services import customer_service
from backend.api.services.encryption_service import seal

router = APIRouter(prefix="/customers", tags=["customers"])


@router.post("", response_model=EncryptedEnvelope, status_code=status.HTTP_201_CREATED)
def create_customer(
    data: CustomerCreate,
    user: User = Depends(get_user_with_public_key),
    db: Session = Depends(get_db),
):
    customer = customer_service.create_customer(db, user, data)
    return seal(user, CustomerOut.model_validate(customer))


@router.get("", response_model=EncryptedEnvelope)
def list_customers(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_user_with_public_key),
    db: Session = Depends(get_db),
):
    customers = customer_service.list_customers(db, user, limit, offset)
    payload = CustomerList(
        items=[CustomerOut.model_validate(c) for c in customers], limit=limit, offset=offset
    )
    return seal(user, payload)


@router.get("/{customer_id}", response_model=EncryptedEnvelope)
def get_customer(
    customer_id: int,
    user: User = Depends(get_user_with_public_key),
    db: Session = Depends(get_db),
):
    customer = customer_service.get_customer(db, user, customer_id)
    return seal(user, CustomerOut.model_validate(customer))


@router.patch("/{customer_id}", response_model=EncryptedEnvelope)
def update_customer(
    customer_id: int,
    data: CustomerUpdate,
    user: User = Depends(get_user_with_public_key),
    db: Session = Depends(get_db),
):
    customer = customer_service.update_customer(db, user, customer_id, data)
    return seal(user, CustomerOut.model_validate(customer))


@router.delete("/{customer_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_customer(
    customer_id: int,
    user: User = Depends(get_current_user),  # no body returned, so no key needed
    db: Session = Depends(get_db),
):
    customer_service.delete_customer(db, user, customer_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
