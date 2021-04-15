#!/usr/bin/env python3
from src.dashboard.webserver.server import app

if __name__ == "__main__":
    app.run(debug=False, port=5000, host="0.0.0.0", use_reloader=False)
