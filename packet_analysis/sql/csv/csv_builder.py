class CSVBuilder:
    """
    Class used to build a collection of "CSV's" used to bulk insert into the DB
    """

    def __init__(self):
        """
        Initializes builder with no SQL objects
        """
        self.sql_objects = {}

    def add_entry(self, table_name: str, items: list):
        """
        Adds a 'csv' entry into the list
        :param table_name: Name of the table to be added to
        :param items: List of strings
        :return: None
        """
        if table_name in self.sql_objects:
            self.sql_objects[table_name].append(tuple(items))
        else:
            self.sql_objects[table_name] = [tuple(items)]
