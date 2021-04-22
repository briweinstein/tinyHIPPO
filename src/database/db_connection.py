from time import time
from sqlalchemy.orm import sessionmaker
from pathlib import Path
from sqlalchemy import create_engine


class DBConnection:
    """Creates a connection to a SQLite Database and manages it"""

    def __init__(self, db_file: str):
        db_file = Path(db_file)
        self.engine = create_engine(f"sqlite:///{db_file}")
        print("Path is:", str(db_file))

        # Bulk DB session variables
        self.session_alert_count = 0
        self.session_alert_time = time()

    def create_session(self):
        """
        Creates a database connection to the SQLite database using this connection's engine
        """
        Session = sessionmaker()
        Session.configure(bind=self.engine)
        self.session = Session()
