# Import everything from the centralized db_config
from db_config import (
    db_config,
    get_db,
    get_session,
    create_tables,
    engine,
    SessionLocal
)

# Re-export for backward compatibility
__all__ = [
    'db_config',
    'get_db',
    'get_session', 
    'create_tables',
    'engine',
    'SessionLocal'
]
