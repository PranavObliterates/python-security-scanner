from flask import Flask

app = Flask(__name__)
# VULNERABLE: Weak hardcoded secret
app.secret_key = "password123"

@app.route("/")
def index():
    return "<h1>Home</h1>"

if __name__ == "__main__":
    app.run()
