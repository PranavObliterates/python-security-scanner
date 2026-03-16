from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)
app.secret_key = "12345" # VULN: Short secret

@app.route("/profile")
def profile():
    user_id = request.args.get("id")
    name = request.args.get("name", "User")
    
    # VULN: SQLi
    conn = sqlite3.connect("test.db")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    user = conn.execute(query).fetchone()
    conn.close()
    
    # VULN: XSS via render_template_string
    template = f"<h1>Profile for {name}</h1>"
    return render_template_string(template)

if __name__ == "__main__":
    app.run(debug=True) # VULN: Debug mode
