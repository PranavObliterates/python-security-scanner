"""Shared pytest fixtures for the security scanner test suite."""
import sqlite3
import os
import pytest
from flask import Flask, request, render_template_string


@pytest.fixture
def vulnerable_app():
    """Create a deliberately vulnerable Flask app for testing."""
    app = Flask(__name__)
    app.secret_key = "password123"
    app.config["TESTING"] = True

    @app.route("/")
    def index():
        return "<h1>Home</h1>"

    @app.route("/user")
    def get_user():
        user_id = request.args.get("id")
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'alice')")
        query = f"SELECT * FROM users WHERE id = {user_id}"
        try:
            result = conn.execute(query).fetchall()
        except Exception as e:
            return str(e), 500
        conn.close()
        return str(result)

    @app.route("/search")
    def search():
        term = request.args.get("q", "")
        return f"<h1>Results for: {term}</h1>"

    @app.route("/profile")
    def profile():
        name = request.args.get("name", "")
        template = f"<h1>Hello {name}</h1>"
        return render_template_string(template)

    @app.route("/login", methods=["POST"])
    def login():
        username = request.form.get("username")
        password = request.form.get("password")
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
        try:
            result = conn.execute(query).fetchone()
        except Exception as e:
            return str(e), 500
        conn.close()
        return "OK" if result else "Failed"

    return app


@pytest.fixture
def safe_app():
    """Create a safe Flask app that uses best practices."""
    app = Flask(__name__)
    app.secret_key = os.urandom(32).hex()
    app.config["TESTING"] = True

    @app.route("/")
    def index():
        return "<h1>Home — Safe App</h1>"

    @app.route("/user")
    def get_user():
        user_id = request.args.get("id")
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'alice')")
        result = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
        conn.close()
        return str(result)

    @app.route("/search")
    def search():
        from markupsafe import escape
        term = request.args.get("q", "")
        return f"<h1>Results for: {escape(term)}</h1>"

    return app


@pytest.fixture
def vulnerable_client(vulnerable_app):
    """Flask test client for the vulnerable app."""
    return vulnerable_app.test_client()


@pytest.fixture
def safe_client(safe_app):
    """Flask test client for the safe app."""
    return safe_app.test_client()
