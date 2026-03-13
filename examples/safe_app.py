from flask import Flask, request, escape, jsonify

app = Flask(__name__)
app.secret_key = "a_long_random_secret_key_change_me"


@app.route("/")
def index():
    return "<h1>Safe App</h1>"


@app.route("/user")
def get_user():
    user_id = request.args.get("id", default=1, type=int)
    return jsonify({"user": f"User {user_id}"})


@app.route("/search")
def search():
    term = request.args.get("q", default="", type=str)
    term_safe = escape(term)
    return f"<h1>Results for: {term_safe}</h1>"


@app.route("/profile")
def profile():
    name = request.args.get("name", default="Guest", type=str)
    name_safe = escape(name)
    return f"<h1>Hello {name_safe}</h1>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
