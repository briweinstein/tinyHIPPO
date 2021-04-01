from requests import Session
from sqlalchemy.orm import sessionmaker
from pathlib import Path
from sqlalchemy import create_engine


class DBConnection:
    """Creates a connection to a SQLite Database and manages it"""

    def __init__(self, db_file: str):
        """
        Creates a database connection to the SQLite database specified by the db_file
        :param db_file: database file
        """
        db_file = Path(db_file)
        engine = create_engine(f"sqlite:///{db_file}")
        self.session = sessionmaker()
        self.session.configure(bind=engine)
        self.session = Session()
