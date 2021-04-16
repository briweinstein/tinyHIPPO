from config import Config
from .database.db_connection import DBConnection
from src.anamoly_detection.anomaly_engine import AnomalyEngine

run_config = Config()
try:
    db = DBConnection(run_config.db_file)
    db.create_session()
    anomaly_engine = AnomalyEngine(db)
except Exception as e:
    db = None
    run_config.log_event.info(f"Database connection error {e}")
try:
    anomaly_engine = AnomalyEngine(db)
except Exception as e:
    anomaly_engine = AnomalyEngine(None)
    run_config.log_event.info(f"Anomaly Engine initialization error: {e}")
