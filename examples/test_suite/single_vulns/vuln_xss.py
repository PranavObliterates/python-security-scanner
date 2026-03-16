from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    term = request.args.get("q", "")
    # VULNERABLE: Reflected XSS
    return f"<h1>Results for: {term}</h1>"

if __name__ == "__main__":
    app.run()
