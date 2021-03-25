CREATE TABLE alerts ( 
	id                   integer NOT NULL  PRIMARY KEY autoincrement ,
	alert_type           alerttype(Privacy, IDS, System) NOT NULL    ,
	device_name          varchar(256)     ,
	device_ip_address    varchar(256)     ,
	device_mac_address   varchar(17)     ,
	timestamp            datetime NOT NULL    ,
	description          text NOT NULL    ,
	payload              text     ,
	severity             enum(0, 1, 2) NOT NULL    
 );

CREATE TABLE anamoly_equations ( 
	id                   integer NOT NULL  PRIMARY KEY autoincrement ,
	average_equation     varchar(256) NOT NULL    ,
	adjustment_equation  varchar(256) NOT NULL    
 );

CREATE TABLE email_information ( 
	id                   integer NOT NULL  PRIMARY KEY autoincrement ,
	recipient_addresses  text     ,
	sender_address       varchar(256) NOT NULL DEFAULT 'openwrt@example.com'   ,
	sender_email_password varchar(32) NOT NULL DEFAULT 'super_secure_password'   ,
	smtp_server          varchar(256) NOT NULL DEFAULT 'smtp.example.com'
 );

CREATE TABLE mac_addresses ( 
	address              varchar(17) NOT NULL  PRIMARY KEY  
 );

