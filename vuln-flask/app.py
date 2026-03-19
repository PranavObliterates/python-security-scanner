from flask import Flask, request, render_template, redirect, url_for, session, render_template_string
import sqlite3
import base64
import pickle

app = Flask(__name__)
app.secret_key = "totally_not_secret"   # Weak secret key (another vuln)

import os
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln.db")

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


# ─────────────────────────────────────────
# HOME
# ─────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("login"))


# ─────────────────────────────────────────
# LOGIN  ← [VULN] SQL INJECTION
# ─────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # ❌ VULNERABLE: raw string formatting — NO parameterized query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(query)          # SQL Injection lives here
        user = cursor.fetchone()
        conn.close()

        if user:
            session["username"] = user["username"]
            session["role"]     = user["role"]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"], role=session["role"])


# ─────────────────────────────────────────
# SEARCH  ← [VULN] SQL INJECTION + REFLECTED XSS
# ─────────────────────────────────────────
@app.route("/search")
def search():
    query_param = request.args.get("q", "")
    results = []

    if query_param:
        # ❌ VULNERABLE SQL: string concatenation
        raw_sql = f"SELECT * FROM users WHERE username LIKE '%{query_param}%'"
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(raw_sql)
        results = cursor.fetchall()
        conn.close()

    # ❌ VULNERABLE XSS: query_param echoed raw via |safe in template
    return render_template("search.html", query=query_param, results=results)


# ─────────────────────────────────────────
# COMMENTS  ← [VULN] STORED XSS
# ─────────────────────────────────────────
@app.route("/comments", methods=["GET", "POST"])
def comments():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        author = session["username"]
        body   = request.form["body"]   # ❌ No sanitization before storage

        conn = get_db()
        conn.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        conn.commit()
        conn.close()
        return redirect(url_for("comments"))

    conn = get_db()
    all_comments = conn.execute("SELECT * FROM comments").fetchall()
    conn.close()

    # ❌ VULNERABLE: comments rendered with |safe — raw HTML/JS executes
    return render_template("comments.html", comments=all_comments)


@app.route("/ssti")
def ssti_demo():
    tmpl = request.args.get("tmpl", "Hello")
    return render_template_string(tmpl)


@app.route("/pickle")
def pickle_demo():
    data = request.args.get("data", "")
    if data:
        try:
            obj = pickle.loads(base64.b64decode(data))
            return str(obj)
        except Exception as e:
            return str(e), 500
    return "No object"


if __name__ == "__main__":
    app.run(debug=True, port=5000)  # debug=True also leaks stack traces (another vuln)
