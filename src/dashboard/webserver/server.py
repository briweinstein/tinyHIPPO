from flask import Flask, render_template, g, redirect, request
from src import run_config
from src.dashboard.webserver.server_utils import get_db, get_neighboring_devices, get_alerts

app = Flask(__name__)


@app.before_request
def init_db():
    g.db = get_db(run_config.db_file)


@app.route('/ids-priv/settings/', methods=['GET', 'POST'])
def settings():
    ip_neighbors = get_neighboring_devices()
    if request.method == 'POST':
        print(request.form)
    return render_template('config.html', neighboring_devices=ip_neighbors)


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
