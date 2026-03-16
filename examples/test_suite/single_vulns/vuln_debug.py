from flask import Flask

app = Flask(__name__)
app.debug = True  # VULNERABLE: Debug mode enabled at app level

@app.route("/")
def index():
    return "<h1>Home</h1>"

if __name__ == "__main__":
    app.run(debug=True)
