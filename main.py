
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY environment variable Render settings mein set karo."
    )

DATABASE = os.environ.get("DATABASE_PATH", "lyne_hosting.db")
HOSTING_DAYS = 5


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            )
        """)


def utc_now():
    return datetime.now(timezone.utc)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({
        "app": "LYNE HOSTING",
        "status": "online"
    })


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or len(password) < 8:
            flash("Sabhi fields bharo. Password kam se kam 8 characters ka ho.")
            return render_template("register.html")

        if len(username) > 40 or len(email) > 254:
            flash("Username ya email bahut lamba hai.")
            return render_template("register.html")

        now = utc_now()
        expires = now + timedelta(days=HOSTING_DAYS)

        try:
            with get_db() as db:
                db.execute("""
                    INSERT INTO users
                    (username, email, password_hash, created_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    username,
                    email,
                    generate_password_hash(password),
                    now.isoformat(),
                    expires.isoformat()
                ))
        except sqlite3.IntegrityError:
            flash("Yeh username ya email pehle se registered hai.")
            return render_template("register.html")

        flash("Account ban gaya! Ab login karo.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))

        flash("Username ya password galat hai.")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as db:
        user = db.execute(
            "SELECT id, username, email, created_at, expires_at, is_admin "
            "FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    expiry = datetime.fromisoformat(user["expires_at"])
    remaining = max(0, (expiry - utc_now()).total_seconds())
    days_left = int((remaining + 86399) // 86400)

    return render_template(
        "dashboard.html",
        user=user,
        days_left=days_left,
        hosting_active=remaining > 0
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
