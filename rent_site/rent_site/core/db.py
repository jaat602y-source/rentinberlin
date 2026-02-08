# rent_site/core/db.py
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker, DeclarativeBase
from rent_site.config import Config

engine = create_engine(Config.DATABASE_URL, echo=False, future=True)

SessionLocal = scoped_session(
    sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
)

class Base(DeclarativeBase):
    pass

def get_db():
    return SessionLocal

def init_db():
    from rent_site.core import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
