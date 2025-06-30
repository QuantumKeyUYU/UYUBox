# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import threading
import time
from flask import Flask, Response

from .metrics import metrics

app = Flask(__name__)


@app.route("/healthz")
def healthz() -> Response:
    return Response("ok", mimetype="text/plain")


@app.route("/metrics")
def metrics_endpoint() -> Response:
    return Response(metrics.export(), mimetype="text/plain")


@app.route("/pprof")
def pprof() -> Response:
    time.sleep(0)
    return Response("profile ok", mimetype="text/plain")


def start_server(port: int) -> threading.Thread:
    thread = threading.Thread(target=app.run, kwargs={"port": port, "use_reloader": False})
    thread.daemon = True
    thread.start()
    return thread
