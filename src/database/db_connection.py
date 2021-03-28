from sqlite3 import connect
from src import run_config
from pathlib import Path
from typing import List


class DBConnection:
    """Creates a connection to a SQLite Database and manages it"""

    def __init__(self, db_file: str):
        """
        Creates a database connection to the SQLite database specified by the db_file
        :param db_file: database file
        """
        db_file = Path(db_file)
        try:
            self.conn = connect(db_file.resolve())
        except Exception as e:
            run_config.log_event(e)
            raise e

    def insert(self, table_name: str, values: List):
        """

        :param table_name:
        :param values:
        :return:
        """
        pass
