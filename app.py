"""
Secure Login System with Attack Prevention — Flask backend
Task 03: Demonstrates password hashing, session-based auth, and
brute-force protection via login attempt limiting + temporary lockout.
"""

import sqlite3
import time
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-this-in-production"  # ok for a learning project

DB_PATH = Path(__file__).parent / "users.db"

MAX_ATTEMPTS = 5          # failed logins allowed before lockout
LOCKOUT_SECONDS = 60      # how long the account stays locked


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until REAL NOT NULL DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def home():
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("That username is already taken.", "error")
            return render_template("register.html")
        finally:
            conn.close()

        flash("Account created. You can log in now.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        now = time.time()

        if user is None:
            conn.close()
            # Same generic message as a wrong password, so attackers can't
            # use this to figure out which usernames exist (no "user enumeration").
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        # --- Check if account is currently locked ---------------------
        if user["locked_until"] and now < user["locked_until"]:
            remaining = int(user["locked_until"] - now)
            conn.close()
            flash(f"Account locked due to too many failed attempts. Try again in {remaining}s.", "error")
            return render_template("login.html")

        # --- Verify password --------------------------------------------
        if check_password_hash(user["password_hash"], password):
            # Successful login: reset attempts, clear lock, start session
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?",
                (user["id"],),
            )
            conn.commit()
            conn.close()
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            # Failed login: increment attempts, lock if threshold reached
            attempts = user["failed_attempts"] + 1
            locked_until = 0
            if attempts >= MAX_ATTEMPTS:
                locked_until = now + LOCKOUT_SECONDS
                attempts = 0  # reset counter for the next lockout window

            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            conn.commit()
            conn.close()

            if locked_until:
                flash(f"Too many failed attempts. Account locked for {LOCKOUT_SECONDS}s.", "error")
            else:
                remaining_tries = MAX_ATTEMPTS - attempts
                flash(f"Invalid username or password. {remaining_tries} attempt(s) left before lockout.", "error")
            return render_template("login.html")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("username"):
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
