import os
from flask import Flask

app = Flask(__name__)
# SAFE: From env
app.secret_key = os.environ.get("FLASK_SECRET", "fallback-if-debug")

@app.route("/")
def hello():
    return "Hello Safe World"

if __name__ == "__main__":
    app.run(debug=False)
