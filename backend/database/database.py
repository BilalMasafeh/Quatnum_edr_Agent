import os
import logging
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

from database.models import Base

logger = logging.getLogger(__name__)

load_dotenv(Path(__file__).parent.parent / ".env")

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "quantum_edr")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

try:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    # Test connection
    with engine.connect() as conn:
        pass
    logger.info(f"Database engine created: postgresql://{DB_HOST}:{DB_PORT}/{DB_NAME}")
except Exception as e:
    logger.warning(f"Failed to connect to PostgreSQL: {e}")
    logger.info("Falling back to SQLite (quantum_edr.db)...")
    
    # SQLite fallback
    sqlite_url = "sqlite:///./quantum_edr.db"
    engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})
    logger.info("Database engine created: SQLite (quantum_edr.db)")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Create all database tables."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise


def get_db():
    """FastAPI dependency: yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()