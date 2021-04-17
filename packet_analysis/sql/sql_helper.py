import sqlite3
from sqlite3 import Error

# All data access objects from __inti__.py -> __all__
from packet_analysis.sql.dao import *

# Bindings for table creation SQL
table_bindings = {
    "ARP": "CREATE TABLE IF NOT EXISTS ARP (\n              {0});".format(arp.table_sql()),
    "DHCP": "CREATE TABLE IF NOT EXISTS DHCP (\n              {0});".format(dhcp.table_sql()),
    "DNS": "CREATE TABLE IF NOT EXISTS DNS (\n              {0});".format(dns.table_sql()),
    "EAPOL": "CREATE TABLE IF NOT EXISTS EAPOL (\n              {0});".format(eapol.table_sql()),
    "Ethernet": "CREATE TABLE IF NOT EXISTS Ethernet (\n              {0});".format(ethernet.table_sql()),
    "IP":  "CREATE TABLE IF NOT EXISTS IP (\n              {0});".format(ip.table_sql()),
    "NTP": "CREATE TABLE IF NOT EXISTS NTP (\n              {0});".format(ntp.table_sql()),
    "TCP": "CREATE TABLE IF NOT EXISTS TCP (\n              {0});".format(tcp.table_sql()),
    "UDP": "CREATE TABLE IF NOT EXISTS UDP (\n              {0});".format(udp.table_sql()),
}

def create_connection(path):
    """
    Create a connection to the DB at the given path
    :param path: Path to .db file
    :return: sqlite3.Connection
    """
    connection = None
    try:
        connection = sqlite3.connect(path)
        print("Connection to SQLite DB successful")
    except Error as e:
        print(f"The error '{e}' occurred")
    return connection

def bulk_insert(conn: sqlite3.Connection, csv_collection: dict):
    """
    Bulk insert data created from the CSVBuilder
    :param conn: DB connection
    :param csv_collection: {} built from CSVBuilder
    :return: None
    """
    # Make sure the tables are present
    for table in csv_collection:
        cursor = conn.cursor()
        cursor.execute(table_bindings[table])
        conn.commit()
        cursor.close()

    # Fill the tables with data
    for table in csv_collection:
        data = csv_collection[table]
        length = len(data[0])
        sql_query = "INSERT INTO {0} VALUES({1})".format(
            str(table), ("?, " * length)[:-2]
        )
        cursor = conn.cursor()
        cursor.executemany(sql_query, data)
        conn.commit()
        cursor.close()

def get_values(conn: sqlite3.Connection, table: str, columns: list, conditions: list) -> list:
    """
    Returns values from the DB based on the given parameters
    :param conn: Connection to the DB
    :param table: Table name
    :param columns: Specific columns to be returned (SELECT clause parameters)
    :param conditions: WHERE clause conditions in the form of [ "a = b" , ... ] -> WHERE a = b AND ...
    :return: list
    """
    # Format the fill query
    sql_str = "SELECT {0} FROM {1} WHERE {2};".format(",".join(columns), table, " AND ".join(conditions))

    # Execute and retrieve rows
    cursor = conn.cursor()
    cursor.execute(sql_str)
    rows = cursor.fetchall()
    cursor.close()
    return rows

def get_count(conn: sqlite3.Connection, table: str, conditions: list) -> int:
    """
    Get the count of rows returned based on the given conditions
    :param conn: Connection to the DB
    :param table: Table name
    :param conditions: WHERE clause conditions in the form of [ "a = b" , ... ] -> WHERE a = b AND ...
    :return: Number of rows returned
    """
    return get_values(conn, table, ["COUNT(*)"], conditions)[0][0]
