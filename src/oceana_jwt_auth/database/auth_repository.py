from sqlalchemy import select
from ..database.db import db, SecIdentity, SecEndpoint


def get_identity(provider, client_type, client_id):
    """
    Get identity information.
    """
    stmt = (
        select(SecIdentity)
        .where(SecIdentity.provider == provider)
        .where(SecIdentity.client_type == client_type)
        .where(SecIdentity.client_id == client_id)
        .where(SecIdentity.enabled == True)  # noqa: E712
    )
    return db.session.execute(statement=stmt).one_or_none()  # .scalars().all()


def get_endpoint_security(provider):

    stmt = (
        select(SecEndpoint).where(SecEndpoint.provider == provider)
    )
    return db.session.execute(statement=stmt).scalars().all()


def get_endpoint_security_dict(provider):
    endpoints = get_endpoint_security(provider)
    return {e.endpoint: e.to_dict() for e in endpoints}
