from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker

from app.config import Config

engine = create_engine(Config.DATABASE_URL, pool_pre_ping=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=False))
Base = declarative_base()


def init_db():
    from app import models  # noqa: F401 (registers model classes on Base.metadata)

    Base.metadata.create_all(bind=engine)
