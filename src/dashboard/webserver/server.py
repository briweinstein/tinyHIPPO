from flask import Flask, render_template, g, request
from src import run_config
from src.dashboard.webserver.server_utils import get_db, get_neighboring_devices, get_alerts
from src.database.models import DeviceInformation, EmailInformation, AnomalyEquations

app = Flask(__name__)


@app.before_request
def init_db():
    g.db = get_db(run_config.db_file)


@app.route('/ids-priv/settings/', methods=['GET', 'POST'])
def settings():
    """
    Serves the template for the ids configuration page
    :return: Rendered jinja-2 template
    """
    ip_neighbors = get_neighboring_devices()
    if request.method == 'POST' and 'device-form' in request.form:
        _device_configuration(request.form, ip_neighbors)
    elif request.method == 'POST' and 'email-form' in request.form:
        _email_configuration(request.form)
    elif request.method == 'POST' and 'equations-form' in request.form:
        _anomaly_configuration(request.form)
    return render_template('config.html',
                           neighboring_devices=ip_neighbors,
                           existing_devices=DeviceInformation.get_mac_addresses(g.db))


def _anomaly_configuration(form_data: dict):
    """
    Handler for anomaly detection configuration form, updates current anomaly configuration settings used in the database
    :param form_data: Form data submitted by the user from the webpage
    :return: nothing
    """
    a = AnomalyEquations(average_equation=form_data['aequations'],
                         adjustment_equation=form_data['sdequations'])
    AnomalyEquations.insert_new_object(a, conn=g.db)


def _email_configuration(form_data: dict):
    """
    Handler for email configuration form, updates current email settings used in the database,
    database only stores one configuration at a time
    :param form_data: Form data submitted by the user from the webpage
    :return: nothing
    """
    e = EmailInformation(recipient_addresses=form_data['raddress'],
                         sender_address=form_data['saddress'],
                         sender_email_password=form_data['password'],
                         smtp_server=form_data['server'])
    EmailInformation.insert_new_object(e, conn=g.db)


def _device_configuration(form_data: dict, ip_neighbors):
    """
    Handler for device configuration form, inserts and removes devices the user would like monitored by the IDS
    :param form_data: Form data submitted by the user from the webpage
    :param ip_neighbors: List of neighboring devices displayed to the user
    :return: nothing
    """
    # insert unique devices into the database to be monitored by our IDS
    mac_addresses = {key for key in form_data.keys()}
    existing_devices = set(DeviceInformation.get_mac_addresses(g.db))
    new_devices_macs = mac_addresses - existing_devices
    new_devices = [neigh for neigh in ip_neighbors if neigh.mac in new_devices_macs]
    for item in new_devices:
        d = DeviceInformation(mac_address=item.mac,
                              name="",
                              ip_address=item.ip)
        DeviceInformation.insert_new_object(d)
    # remove devices that were unchecked
    devices_to_delete = [DeviceInformation.get_by_pk(DeviceInformation.mac_address, mac_address, g.db) for mac_address
                         in
                         existing_devices - mac_addresses]
    for device in devices_to_delete:
        device.delete(False, g.db)
    DeviceInformation.safe_commit(g.db)


@app.route('/ids-priv/ids-alerts/')
def ids_alerts():
    """
    Serves template for the ids alerts page
    :return: Rendered jinja-2 template
    """
    all_alerts = get_alerts('IDS', connection=g.db, limit_num=20)
    return render_template('alerts.htm', all_alerts=all_alerts, dashboard_title='IDS')


@app.route('/ids-priv/privacy-alerts/')
def privacy_alerts():
<<<<<<< HEAD
    all_alerts = get_alerts('Privacy', g.db)
=======
    """
    Serves template for the privacy alerts page
    :return: Rendered jinja-2 template
    """
    all_alerts = get_alerts('Privacy', connection=g.db, limit_num=20)
>>>>>>> c5cfbe3c985cfb5e02a328b672dc0b5bd5005138
    return render_template('alerts.htm', all_alerts=all_alerts, dashboard_title='Privacy')


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
