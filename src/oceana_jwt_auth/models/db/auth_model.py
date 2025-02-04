from sqlalchemy import Column, PrimaryKeyConstraint, inspect

from ...database.db import db
from ...config import Config  # noqa: F401
from ...utils import EXTENSION_BIND

# CREATE TABLE frn.sec_identity (
# 	provider varchar(200) NOT NULL,
# 	client_type varchar(200) NOT NULL,
# 	client_id varchar(1000) NOT NULL,
# 	client_hash varchar(1000) NOT NULL,
# 	client_salt varchar(200) NOT NULL,
# 	roles varchar(1000) NULL,
# 	CONSTRAINT sec_identity_pkey PRIMARY KEY (provider, client_type, client_id)
# );


class SecIdentity(db.Model):
    """
    Data model for Identity

    Attributes:
        provider (srt): Provider name
        client_type (str): Client type
        client_id (str): Client ID
        client_hash (str): Client hash
        client_salt (str): Client salt
        roles (str): Roles given to the provider
        enabled (bool): Client enabled
    """
    __bind_key__ = EXTENSION_BIND
    __tablename__ = "sec_identity"
    __table_args__ = (
        PrimaryKeyConstraint("provider", "client_type", "client_id"),
        {
            "extend_existing": True,
            "schema": Config.DB_SCHEMA
        }
    )

    provider = db.Column(db.String(200), primary_key=True)
    client_type = db.Column(db.String(200), primary_key=True)
    client_id = db.Column(db.String(1000), primary_key=True)
    client_hash = db.Column(db.String(1000), nullable=False)
    client_salt = db.Column(db.String(200), nullable=False)
    roles = db.Column(db.String(1000), nullable=True)
    enabled = db.Column(db.Boolean, default=True)

    def __init__(self, provider, client_type, client_id, client_hash, client_salt, roles, enabled):
        self.provider = provider
        self.client_type = client_type
        self.client_id = client_id
        self.client_hash = client_hash
        self.client_salt = client_salt
        self.roles = roles
        self.enabled = enabled

    def to_dict(self):  # pragma: no cover
        # Convert roles to dictionary
        return {c.key: getattr(self, c.key) if c.key != "roles" else
                [r.strip().lower() for r in str(getattr(self, c.key)).strip().split(",")]
                for c in inspect(self).mapper.column_attrs}

    def __str__(self):  # pragma: no cover
        return ", ".join([f"{c.key}: {getattr(self, c.key)}" for c in inspect(self).mapper.column_attrs])


# CREATE TABLE frn.sec_endpoint (
#     provider varchar(200) NOT NULL,
#     endpoint varchar(200) NOT NULL,
#     roles varchar(1000) NOT NULL,
#     url_template varchar(1000) NULL,
#     description varchar(1000) NULL,
#     CONSTRAINT sec_endpoint_pkey PRIMARY KEY (provider, endpoint)
# );

class SecEndpoint(db.Model):
    __bind_key__ = EXTENSION_BIND
    __tablename__ = "sec_endpoint"
    __table_args__ = (
        PrimaryKeyConstraint("provider", "endpoint"),
        {
            "extend_existing": True,
            "schema": Config.DB_SCHEMA
        }
    )

    provider = Column(db.String(200), primary_key=True)
    endpoint = Column(db.String(200), primary_key=True)
    roles = Column(db.String(1000), nullable=False)
    url_template = Column(db.String(1000), nullable=True)
    description = Column(db.String(1000), nullable=True)

    def __init__(self, provider, endpoint, roles, url_template, description):
        self.provider = provider
        self.endpoint = endpoint
        self.roles = roles
        self.url_template = url_template
        self.description = description

    def to_dict(self):
        # Convert roles to dictionary
        return {c.key: getattr(self, c.key) if c.key != "roles" else
                [r.strip().lower() for r in str(getattr(self, c.key)).strip().split(",")]
                for c in inspect(self).mapper.column_attrs}

    def __str__(self):  # pragma: no cover
        return ", ".join([f"{c.key}: {getattr(self, c.key)}" for c in inspect(self).mapper.column_attrs])
