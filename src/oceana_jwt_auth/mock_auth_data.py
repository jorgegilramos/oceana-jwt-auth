from .config import OCEANA_API_PROVIDER
from .database.db import db, SecIdentity, SecEndpoint


def populate_identity_data():
    identities = [
        SecIdentity(
            provider=OCEANA_API_PROVIDER,
            client_type="application",
            client_id="oceana-admin",
            # client_secret = "bad_password"
            client_hash="e63fb8fb1bc2de9836798fb9eb87b393fc0c6e23506ed5ad962e3140c9582fa1",
            client_salt="f19t70fRqbeKRgdB9LdoW1wf0o5oT_eLSPNotue4GsM=",
            roles="admin",
            enabled=True),
        SecIdentity(
            provider=OCEANA_API_PROVIDER,
            client_type="application",
            client_id="oceana-reader",
            # client_secret = "bad_password"
            client_hash="546f797e7465aa179c42df05ff7c6842988ed82f84e18a9a0bd6c75828d3d838",
            client_salt="2yInlAvKMJvJMKjnTBV_bgiHsvCkcnt0kuGVXqxSGv4=",
            roles="reader",
            enabled=True),
        SecIdentity(
            provider=OCEANA_API_PROVIDER,
            client_type="application",
            client_id="oceana-writer",
            # client_secret = "bad_password"
            client_hash="ac193d5ef24419e3ab3afaac5614a0eaf95597e1a77116440eb2cc8d68fc536e",
            client_salt="A-vbqAXkos6geH3-q6dwciVH6cbLRziOCPyJp4A8PLM=",
            roles="reader,writer",
            enabled=True),
    ]
    for identity in identities:
        db.session.add(identity)
    db.session.commit()


def populate_endpoint_security_data():
    endpoints = [
        SecEndpoint(
            provider=OCEANA_API_PROVIDER,
            endpoint="TestApp.get",
            roles="admin",
            url_template="/v1/test",
            description="Test Endpoint"),
    ]

    for endpoint in endpoints:
        db.session.add(endpoint)
    db.session.commit()
