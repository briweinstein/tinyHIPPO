from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text, VARCHAR
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from sqlalchemy.orm import relationship
from src import db, run_config

Base = declarative_base()


class BaseModelMixin:
    """Base class with default functionality for all models"""

    @classmethod
    def insert_new_object(cls, model_object: Base, commit=True):
        """
        Adds this model object to the session and optionally commits to the database
        :param model_object: Object to add to the database
        :param commit: Whether to commit to the database after adding the model object
        :return: Object that was inserted
        """
        db.session.add(model_object)
        if commit:
            model_object.safe_commit()
        else:
            return model_object

    @staticmethod
    def safe_commit():
        """Tries to commit to this database session and rolls back if an error occurs"""
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            run_config.log_event(f"Exception occurred when committing to the database: {e}")

    @classmethod
    def get_by_pk(cls, key, value):
        """
        Returns the first model object that matches the given primary key's value
        :param key: The primary key to check against (IE alert_id, mac_address)
        :param value: The value tied to the primary key to fetch from the table
        :return: The corresponding model object
        """
        return db.session.query(cls).filter(key == value).first()

    def delete(self, with_commit=True):
        """
        Deletes this entry from the database with the option to commit the changes
        :param with_commit: Whether to commit to the database
        :return: The object deleted
        """
        db.session.delete(self)
        if with_commit:
            self.safe_commit()
        return self


class DeviceInformation(Base, BaseModelMixin):
    """Model mapping a row of our DeviceInformation table in our SQLite Database"""
    __tablename__ = "device_information"
    mac_address = Column(String(17), primary_key=True, nullable=False)
    name = Column(String(256))
    ip_address = Column(String(256))
    alerts = relationship('Alerts', back_populates='device')


class Alerts(Base, BaseModelMixin):
    """Model mapping a row of our Alerts table in our SQLite Database"""
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, nullable=False)
    alert_type = Column(Text, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.now())
    description = Column(Text, nullable=False)
    severity = Column(Integer, nullable=False)
    mac_address = Column(VARCHAR(17), ForeignKey("device_information.mac_address"))
    device = relationship('DeviceInformation', back_populates='alerts')
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
