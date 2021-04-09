from flask import Flask, render_template, g, request
from src import run_config
from src.dashboard.webserver.server_utils import get_db, get_neighboring_devices, get_alerts, devices_in_db
from src.database.models import DeviceInformation

app = Flask(__name__)


@app.before_request
def init_db():
    g.db = get_db(run_config.db_file)


@app.route('/ids-priv/settings/', methods=['GET', 'POST'])
def settings():
    ip_neighbors = get_neighboring_devices()
    if request.method == 'POST':
        # insert unique devices into the database to be monitored by our IDS
        mac_addresses = {key for key in request.form.keys()}
        existing_devices = set(devices_in_db(list(mac_addresses), g.db))
        new_devices_macs = mac_addresses - existing_devices
        new_devices = [neigh for neigh in ip_neighbors if neigh.mac in new_devices_macs]
        for item in new_devices:
            d = DeviceInformation(mac_address=item.mac,
                                  name="placeholder",
                                  ip_address=item.ip)
            DeviceInformation.insert_new_object(d)
        # remove devices that were unchecked
        devices_to_delete = [DeviceInformation.get_by_pk(DeviceInformation.mac_address, mac_address, g.db) for mac_address in
                             existing_devices - mac_addresses]
        for device in devices_to_delete:
            device.delete(False, g.db)
        DeviceInformation.safe_commit(g.db)

    return render_template('config.html',
                           neighboring_devices=ip_neighbors,
                           existing_devices=DeviceInformation.get_mac_addresses())


@app.route('/ids-priv/ids-alerts/')
def ids_alerts():
    all_alerts = get_alerts('IDS', g.db)
    return render_template('alerts.htm', all_alerts=all_alerts, dashboard_title='IDS')


@app.route('/ids-priv/privacy-alerts/')
def privacy_alerts():
    all_alerts = get_alerts('Privacy', g.db)
    return render_template('alerts.htm', all_alerts=all_alerts, dashboard_title='Privacy')


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
