from flask import Flask, request
from markupsafe import escape
import os

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()  # SAFE: Strong random key

@app.route("/search")
def search():
    term = request.args.get("q", "")
    # SAFE: Escaped
    return f"<h1>Results: {escape(term)}</h1>"

if __name__ == "__main__":
    app.run()
