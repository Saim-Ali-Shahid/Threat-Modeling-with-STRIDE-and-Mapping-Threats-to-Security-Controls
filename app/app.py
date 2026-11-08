import logging
import os
import sqlite3

import requests
from flask import Flask, request, session

logging.basicConfig(filename="audit.log", level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("audit")

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
LOCK_API_KEY = os.environ["LOCK_API_KEY"]
DB = "urbanbike.db"


def db():
    return sqlite3.connect(DB)


def audit_log(action, **details):
    log.info("%s user=%s %s", action, session.get("uid"), details)


def require_auth(*roles):                       # deny by default, check on every request
    def deco(fn):
        def wrapper(*a, **k):
            if "uid" not in session or (roles and session.get("role") not in roles):
                return "Forbidden", 403
            return fn(*a, **k)
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco


@app.route("/login", methods=["POST"])
def login():
    u = request.form["username"]
    p = request.form["password"]
    row = db().execute("SELECT id, role FROM riders WHERE name=? AND pw=?", (u, p)).fetchone()
    if row:
        session["uid"] = row[0]
        session["role"] = row[1]
    return ("OK", 200) if row else ("Invalid", 401)


@app.route("/unlock", methods=["POST"])
@require_auth("rider")
def unlock():
    try:
        requests.post("https://locks.example.com/unlock",
                      data={"bike": request.form["bike_id"], "key": LOCK_API_KEY},
                      timeout=5)
        audit_log("unlock", bike=request.form["bike_id"])
        return "Unlocked"
    except Exception:
        log.exception("unlock failed")
        return "Service unavailable", 500


@app.route("/rides")
@require_auth("rider", "operator")
def rides():
    rid = request.args.get("rider_id", "")
    if session["role"] != "operator" and str(session["uid"]) != rid:
        return "Forbidden", 403
    rows = db().execute("SELECT bike, start, cost FROM rides WHERE rider_id=?", (rid,)).fetchall()
    return str(rows)


@app.route("/refund", methods=["POST"])
@require_auth("operator")
def refund():
    db().execute("UPDATE rides SET cost=0 WHERE id=?", (request.form["ride_id"],))
    audit_log("refund", ride_id=request.form["ride_id"])
    return "Refunded"


@app.route("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
