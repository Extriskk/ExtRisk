"""
Database engine, session factory, and Base for ORM models.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from api.config import settings

"""
Database engine, session factory, and Base for ORM models.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from api.config import settings

_url = settings.DATABASE_URL
if _url.strip().lower().startswith("sqlite"):
    engine = create_engine(
        _url,
        connect_args={"check_same_thread": False, "timeout": 30},
    )
else:
    engine = create_engine(
        _url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a DB session, closes on exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
