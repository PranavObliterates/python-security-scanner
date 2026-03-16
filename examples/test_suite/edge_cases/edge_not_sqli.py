from flask import Flask
import os

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()

@app.route("/logs")
def show_logs():
    # EDGE CASE: 'SELECT' is in the string, but it's not a query
    msg = "User selected the option"
    return f"<p>Info: {msg}</p>"

if __name__ == "__main__":
    app.run()
