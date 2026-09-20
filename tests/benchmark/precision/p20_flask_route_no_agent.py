"""Precision fixture: a plain Flask view must yield ZERO findings at defaults.

Reduced from pallets/flask examples/tutorial/flaskr/auth.py:66 — a repository
this project pins with category "control", where corpus-triage.json says any
finding is a precision failure by definition.

Nothing here is agent-related: no agent framework is imported, the SQL is
parameterised, and the handler is an ordinary web view. It was reported as
HIGH DATABASE-MUTATE because "route" was a BARE name in
reachability.resource_boundary_decorators and that signal was on by default.

At defaults this file must produce nothing. With --resource-boundary it is
expected to produce the DATABASE-MUTATE finding again — at that point the
user has asked for web route handlers to count as entry points, and the
finding is the answer to the question they asked.
"""

import sqlite3

from flask import Blueprint, request
from werkzeug.security import generate_password_hash

bp = Blueprint("auth", __name__, url_prefix="/auth")


def get_db():
    return sqlite3.connect("flaskr.sqlite")


@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        error = None

        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."

        if error is None:
            db.execute(
                "INSERT INTO user (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            db.commit()
    return "ok"
