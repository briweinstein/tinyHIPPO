CREATE TABLE alerts (
	id                   integer NOT NULL  PRIMARY KEY autoincrement ,
	alert_type           text CHECK (alert_type IN ('Privacy', 'IDS', 'System')) NOT NULL    ,
	timestamp            datetime NOT NULL    ,
	description          text NOT NULL    ,
	severity             integer check (severity in (0, 1, 2)) NOT NULL
	mac_address          varchar(17)     ,
	payload              text     ,
 );

CREATE TABLE anomaly_equations (
	id                   integer NOT NULL  PRIMARY KEY autoincrement ,
	average_equation     varchar(256) NOT NULL    ,
	adjustment_equation  varchar(256) NOT NULL    
 );

CREATE TABLE email_information ( 
	id                   integer NOT NULL  PRIMARY KEY autoincrement ,
	recipient_addresses  text    NOT NULL ,
	sender_address       varchar(256) NOT NULL,
	sender_email_password varchar(32) NOT NULL,
	smtp_server          varchar(256) NOT NULL
 );

CREATE TABLE device_information (
	mac_address          varchar(17) NOT NULL PRIMARY KEY,
	device_name          varchar(256)     ,
    device_ip_address    varchar(256)     ,
 );