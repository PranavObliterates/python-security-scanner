from flask import Flask, request, render_template, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = "totally_not_secret"   # Weak secret key (another vuln)

DB = "vuln.db"

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


if __name__ == "__main__":
    app.run(debug=True, port=5000)  # debug=True also leaks stack traces (another vuln)
