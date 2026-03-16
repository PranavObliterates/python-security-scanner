from flask import Flask, request
import os
import sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("test.db")
    # SAFE: Parameterized
    result = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
    conn.close()
    return str(result)

if __name__ == "__main__":
    app.run(debug=False)
