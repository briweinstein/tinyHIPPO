from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


class Alerts(Base):
    """Represents the Alerts table in our SQLite Database"""
    __tablename__ = "Alerts"
    alert_id = Column(Integer, primary_key=True, nullable=False)
    alert_type = Column(String, nullable=False)
    timestamp = Column(String, nullable=False, default=datetime.now())
    description = Column(String, nullable=False)
    severity = Column(Integer, nullable=False)
    mac_address = Column(String(17), ForeignKey("device_information.mac_address"))
    payload = Column(String)


class AnomalyEquations(Base):
    """Represents the AnomalyEquation table in our SQLite Database"""
    __tablename__ = "anomaly_equations"
    equation_id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    average_equation = Column(String(256), nullable=False)
    adjustment_equation = Column(String(256), nullable=False)


class EmailInformation(Base):
    """Represents the EmailInformation table in our SQLite Database"""
    __tablename__ = "email_information"
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    recipient_addresses = Column(String, nullable=False)
    sender_addresses = Column(String(256), nullable=False)
    sender_email_password = Column(String(32), nullable=False)
    smtp_server = Column(String(256), nullable=False)


class DeviceInformation(Base):
    """Represents the DeviceInformation table in our SQLite Database"""
    __tablename__ = "device_information"
    mac_address = Column(String, primary_key=True, nullable=False)
    device_name = Column(String)
    device_ip_address = Column(String)
