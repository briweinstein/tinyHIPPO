#!/usr/bin/env python3

import os
import sqlite3

from pathlib import Path

install_path = Path(os.getenv("TINYHIPPO_INSTALL_PATH"))

def absolute_path(relative_path: str) -> Path:
    return install_path / relative_path

queries = [
    "CREATE TABLE mac_addresses (id integer NOT NULL PRIMARY KEY autoincrement, address varchar(17) NOT NULL);",
    "CREATE TABLE anamoly_equations (id integer NOT NULL PRIMARY KEY autoincrement, average_equation varchar(256) NOT NULL, adjustment_equation varchar(256) NOT NULL);",
    "CREATE TABLE email_information (id integer NOT NULL PRIMARY KEY autoincrement, recipient_addresses text, sender_address varchar(256) NOT NULL DEFAULT 'openwrt@example.com', sender_email_password varchar(32) NOT NULL DEFAULT 'super_secure_password', smtp_server varchar(256) NOT NULL DEFAULT 'smtp.example.com');",
    "CREATE TABLE alerts (id integer NOT NULL  PRIMARY KEY autoincrement, alert_type text CHECK (alert_type IN ('Privacy', 'IDS', 'System')) NOT NULL, device_name varchar(256), device_ip_address varchar(256), device_mac_address varchar(17), timestamp datetime NOT NULL, description text NOT NULL, payload text, severity integer check (severity in (0, 1, 2)) NOT NULL);"
]

# If the Sqlite database exists already, remove it
try:
    os.remove(absolute_path("tinyHIPPO.sqlite"))
except:
    pass

db = sqlite3.connect(absolute_path("tinyHIPPO.sqlite"))
for q in queries:
    db.execute(q)
    db.commit()
db.close()

