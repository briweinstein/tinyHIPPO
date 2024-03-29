from config import Config
from .database.db_connection import DBConnection

run_config = Config()
try:
    db = DBConnection(run_config.db_file)
    db.create_session()
except Exception as e:
    run_config.log_event.info(f"Database connection error {e}")

