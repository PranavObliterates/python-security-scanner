"""Safe Flask app — uses best practices. Scanner should find ZERO code vulnerabilities."""
import os
import sqlite3
from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)
# SAFE: Secret key from environment variable (or a long random fallback for dev)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())


@app.route("/")
def index():
    return "<h1>Home — Safe App</h1>"


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("test.db")
    # SAFE: Parameterized query prevents SQL injection
    query = "SELECT * FROM users WHERE id = ?"
    result = conn.execute(query, (user_id,)).fetchall()
    conn.close()
    return str(result)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    # SAFE: Using markupsafe.escape() to prevent XSS
    return f"<h1>Results for: {escape(term)}</h1>"


@app.route("/profile")
def profile():
    name = request.args.get("name", "")
    # SAFE: Escaped output
    safe_name = escape(name)
    return f"<h1>Hello {safe_name}</h1>"


if __name__ == "__main__":
    # SAFE: debug=False in production
    app.run(debug=False)
