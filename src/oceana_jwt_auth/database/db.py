from flask_sqlalchemy import SQLAlchemy
from ..config import Config
from ..utils import info

db = SQLAlchemy()

# Important to use create_all() tables in SQLAlchemy. Do not remove!!!
from ..models.db import SecEndpoint, SecIdentity  # noqa: E402,F401


def init_app(config_object, testing):

    # Simulate schema in sqlite
    sqlite_schema()

    # Create all necessary database entities
    if (hasattr(config_object, "DB_CREATE_ENTITIES") and bool(config_object.DB_CREATE_ENTITIES)) or testing:
        db.create_all()
        info("Database Model Initialized")


def sqlite_schema():

    # Simulate schema in sqlite
    if db.engine.url.get_backend_name() == "sqlite":
        connection = db.engine.raw_connection()
        try:
            # Get a SQLite cursor from the connection
            cursor = connection.cursor()
            # Execute the ATTACH DATABASE command
            cursor.execute(f"attach database ':memory:' as '{Config.DB_SCHEMA}'")
            # Commit the transaction
            connection.commit()
        finally:
            # Close the connection
            connection.close()
