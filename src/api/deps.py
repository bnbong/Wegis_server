# --------------------------------------------------------------------------
# API dependency management module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from src.database import DBManager


def get_db_manager() -> DBManager:
    """
    Provide DB manager instance for API usage
    """
    return DBManager()


def get_db():
    """
    Provide PostgreSQL session for API usage
    """
    db_manager = get_db_manager()
    db = db_manager.get_postgres_session()
    try:
        yield db
    finally:
        db.close()
