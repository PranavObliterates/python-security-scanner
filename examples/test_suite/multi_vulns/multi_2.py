from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/admin/update", methods=["POST"])
def update_user():
    # VULN: Missing CSRF
    username = request.form.get("username")
    new_pass = request.form.get("password")
    
    # VULN: SQLi via concat
    conn = sqlite3.connect("test.db")
    query = "UPDATE users SET password = '" + new_pass + "' WHERE username = '" + username + "'"
    conn.execute(query)
    conn.commit()
    conn.close()
    return "Updated"

@app.route("/admin/check")
def check():
    auth = "admin:admin123" # VULN: Hardcoded creds
    return f"Admin status: {auth}"

if __name__ == "__main__":
    app.run()
