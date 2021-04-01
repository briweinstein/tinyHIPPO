from typing import List

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text, VARCHAR
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from src import db, run_config

Base = declarative_base()


class BaseModelMixin:
    """Base class with default functionality for all models"""

    def insert_new(self, commit=True):
        """
        Adds this model object to the session and optionally commits to the database
        :param commit: Whether to commit to the database after adding the model object
        :return: Object that was inserted
        """
        db.session.add(self)
        if commit:
            self.safe_commit()
        else:
            return self

    @staticmethod
    def safe_commit():
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            run_config.log_event(e)

    @classmethod
    def get_by_pk(cls, key, value):
        return db.session.query(cls).filter(key == value).first()


class Alerts(Base, BaseModelMixin):
    """Model mapping a row of our Alerts table in our SQLite Database"""
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, nullable=False)
    alert_type = Column(Text, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.now())
    description = Column(Text, nullable=False)
    severity = Column(Integer, nullable=False)
    mac_address = Column(VARCHAR(17), ForeignKey("device_information.mac_address"))
    payload = Column(Text)


class AnomalyEquations(Base, BaseModelMixin):
    """Model mapping a row of our AnomalyEquation table in our SQLite Database"""
    __tablename__ = "anomaly_equations"
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    average_equation = Column(String(256), nullable=False)
    adjustment_equation = Column(String(256), nullable=False)


class EmailInformation(Base, BaseModelMixin):
    """Model mapping a row of our EmailInformation table in our SQLite Database"""
    __tablename__ = "email_information"
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    recipient_addresses = Column(String, nullable=False)
    sender_address = Column(String(256), nullable=False)
    sender_email_password = Column(String(32), nullable=False)
    smtp_server = Column(String(256), nullable=False)


class DeviceInformation(Base, BaseModelMixin):
    """Model mapping a row of our DeviceInformation table in our SQLite Database"""
    __tablename__ = "device_information"
    mac_address = Column(String(17), primary_key=True, nullable=False)
    device_name = Column(String(256))
    device_ip_address = Column(String(256))
