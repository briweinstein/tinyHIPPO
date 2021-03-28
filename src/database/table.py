import abc
from sqlite3 import connect
from sqlite3 import Connection
from typing import List

class Table(abc.ABC):
    """Represents an abstract table within a database that implements management functions"""
    @abc.abstractmethod
    def insert(self, connection:Connection, values:List):
        """
        Inserts the given values into this table using the given database connection
        :param connection: Connection to SQLite database
        :param values: Values to insert
        :return:
        """
        raise NotImplementedError

    @abc.abstractmethod
    def delete(self):
        pass
