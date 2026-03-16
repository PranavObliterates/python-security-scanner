"""Intentionally vulnerable Flask app for testing the scanner."""
from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)
app.secret_key = "password123"  # VULN: weak hardcoded secret


@app.route("/")
def index():
    return "<h1>Home</h1>"


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("test.db")
    # VULN: SQL Injection via f-string
    query = f"SELECT * FROM users WHERE id = {user_id}"
    try:
        result = conn.execute(query).fetchall()
    except Exception as e:
        conn.close()
        return str(e), 500
    conn.close()
    return str(result)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    # VULN: Reflected XSS — user input directly in HTML
    return f"<h1>Results for: {term}</h1>"


@app.route("/profile")
def profile():
    name = request.args.get("name", "")
    # VULN: XSS via render_template_string
    template = f"<h1>Hello {name}</h1>"
    return render_template_string(template)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect("test.db")
    # VULN: SQL Injection via string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    try:
        result = conn.execute(query).fetchone()
    except Exception as e:
        conn.close()
        return str(e), 500
    conn.close()
    return "OK" if result else "Failed"


@app.route("/admin")
def admin():
    # VULN: Hardcoded credentials in source
    admin_password = "supersecret123"
    api_token = "sk-1234567890abcdef"
    return f"<h1>Admin Panel</h1>"


@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    # VULN: Open redirect (not currently detected, but good test case)
    return f'<meta http-equiv="refresh" content="0;url={url}">'


if __name__ == "__main__":
    app.run(debug=True)  # VULN: debug mode enabled
