import sqlite3
from sqlite3 import Error

# All data access objects from __inti__.py -> __all__
from .dao import *

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
    Creates a connection to the DB at the given path
    :param path: String of the path to the .db file
    :return: A SQLite connection
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
    Bulk inserts data in the SQLite database
    :param conn: The connection object
    :param csv_collection: The collection of data to be inserted
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
        print("SQL: " + sql_query)
        print("Data: " + str(data[0]))
        cursor = conn.cursor()
        cursor.executemany(sql_query, data)
        conn.commit()
        cursor.close()
