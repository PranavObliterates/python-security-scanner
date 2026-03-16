from flask import Flask, render_template
import os

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()  # SAFE: Strong random key

@app.route("/")
def index():
    # SAFE: Template auto-escaping
    return render_template("index.html", content="<b>test</b>")

if __name__ == "__main__":
    app.run(debug=False)
