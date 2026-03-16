from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("test.db")
    # VULNERABLE: SQL Injection via f-string
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = conn.execute(query).fetchall()
    conn.close()
    return str(result)

if __name__ == "__main__":
    app.run()
