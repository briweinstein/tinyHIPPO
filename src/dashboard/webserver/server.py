from flask import Flask, render_template, g
from .server_utils import get_alerts, get_neighboring_devices, get_db
from src import run_config

app = Flask(__name__)


@app.before_request
def init_db():
    g.db = get_db(run_config.db_file)

@app.route('/ids-priv/settings/')
def settings():
    pass


@app.route('/ids-priv/ids-alerts/')
def ids_alerts():
    all_alerts = get_alerts('IDS',g.db)
    return render_template('alerts.htm', all_alerts=all_alerts, dashboard_title='IDS')


@app.route('/ids-priv/privacy-alerts/')
def privacy_alerts():
    all_alerts = get_alerts('Privacy', g.db)
    return render_template('alerts.htm', all_alerts=all_alerts, dashboard_title='Privacy')


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
