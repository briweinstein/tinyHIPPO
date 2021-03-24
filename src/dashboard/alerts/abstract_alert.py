import abc
import json
from src import run_config as CONFIG
from src.emailalerts import emailsystem

class ALERT_TYPE:
    PRIVACY = "Privacy"
    IDS = "IDS"
    UNKNOWN = "Unknown"

class SEVERITY:
    INFO = 0
    WARN = 1
    ALERT = 2

class Alert(abc.ABC):
    """
    This abstract base class represents a single alert in our system
    """

    # Required properties
    @property
    @abc.abstractmethod
    def severity(self):
        pass

    @property
    @abc.abstractmethod
    def type(self):
        pass

    # Required methods
    @abc.abstractmethod
    def jsonify(self):
        raise NotImplementedError

    # Common methods
    def alert(self):
        """
        Send the alert where it should go
        :return:
        """
        # Send email if urgent enough
        if self.severity > 1:
            emailsystem.send_email_alert(self)

        # Log the alert to the log file
        self.log_alert()

        # Save the alert in the JSON collection for frontend use
        self.save_alert()

    def save_alert(self):
        """
        Saves the alert object in JSON format to the collection
        :return:
        """
        path = CONFIG.alert_collection_path

        # Open alert collection file to read
        alert_data = None
        with open(path, 'r') as alert_collection:
            try:
                alert_data = json.load(alert_collection)
            except json.decoder.JSONDecodeError:
                alert_data = json.loads("{\n \"alerts\": []\n}\n")

            # Get the list of alerts, add the current object to the list
            alerts = alert_data["alerts"]
            alerts.append(self.jsonify())

        # Load object as JSON
        serialized_data = json.dumps(alert_data, indent=4)

        # Write to file
        write_alert_collection = open(path, 'w')
        write_alert_collection.write(serialized_data)
        write_alert_collection.close()

    def log_alert(self):
        """
        Logs the alert object to the log file
        :return:
        """
        log_file = "unknown_error.log"
        if self.type == ALERT_TYPE.IDS:
            log_file = "ids_alerts.log"
        elif self.type == ALERT_TYPE.PRIVACY:
            log_file = "privacy_alerts.log"
        f = open(log_file, "a")
        f.write(str(self))
        f.close()
