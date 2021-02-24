# Email Alerts

The following describes how to use the email alerting feature of the Capstone IDS.

### Using the Email Alerting Feature

In your Python code, import the email alerting features and use the send_email_alert() function to 
send a properly formatted email alert.
```
from emailalerts import emailsystem
emailsystem.send_email_alert("Security", "Creppy Robot Camera", "192.168.100.100", "AB:CD:EF:12:34:56", "Feb 14, 2021, 21:35", "Test Information")
```

### Email Account Configuration
The following example config is what the email system will read from to get the proper account details
to send the email.
```
{
    "email": {
        "smtp_server": "smtp.example.com",
        "email_account": "openwrt@example.com",
        "email_password": "super_secure_password",
        "recipient_email": "homeowner@example.com"
    },
    "mac_addrs": ["AA:BB:CC:DD:EE:FF"]
}
```
This configuration file can be found in /etc/capstone-ids/