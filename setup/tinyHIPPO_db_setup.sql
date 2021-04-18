CREATE TABLE alerts (
	id                   integer NOT NULL  PRIMARY KEY,
	alert_type           text CHECK (alert_type IN ('Anomaly', 'Privacy', 'IDS', 'System')) NOT NULL,
	timestamp            text NOT NULL,
	description          text NOT NULL,
	severity             integer check (severity in (0, 1, 2)) NOT NULL,
	mac_address          varchar(17),
	payload              text,
	FOREIGN KEY(mac_address) REFERENCES device_information(mac_address)
 );

CREATE TABLE anomaly_equations (
	id                   integer NOT NULL  PRIMARY KEY AUTOINCREMENT,
	average_equation     varchar(256) NOT NULL    ,
	deviation_equation   varchar(256) NOT NULL    ,
	layer                varchar(256) NOT NULL    ,
	window_size          integer      NOT NULL    ,
	interval_size        integer      NOT NULL
 );

CREATE TABLE email_information ( 
	id                   integer NOT NULL  PRIMARY KEY,
	recipient_addresses  text    NOT NULL ,
	sender_address       varchar(256) NOT NULL,
	sender_email_password varchar(32) NOT NULL,
	smtp_server          varchar(256) NOT NULL
 );

CREATE TABLE device_information (
	mac_address          varchar(17) NOT NULL PRIMARY KEY,
	name          varchar(256),
    ip_address    varchar(256)
 );