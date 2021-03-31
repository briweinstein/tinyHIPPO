from config import Config
from .database.db_connection import DBConnection

run_config = Config()
db = DBConnection(run_config.db_file)
