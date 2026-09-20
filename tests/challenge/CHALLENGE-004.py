"""CHALLENGE-004 fixture: a plain Flask view reported as a finding.

Reduced from pallets/flask examples/tutorial/flaskr/auth.py:66. That repo is
pinned in this project's own corpus with category "control": per
tests/benchmark/corpus-triage.json, any finding in a control repo is a
precision failure by definition.

Nothing here is agent-related. No agent framework is imported anywhere in
the repository this is reduced from. The SQL is parameterised. The only
reason it is reported is that "route" appears as a BARE name in
reachability.resource_boundary_decorators, which is on by default, so
@bp.route("/register") matches and the view is treated as a HIGH-confidence
entry point.
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
