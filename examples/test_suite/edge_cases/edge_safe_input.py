from flask import Flask, request
import os

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()

@app.route("/greet")
def greet():
    # EDGE CASE: Uses 'request.args', but only for text, no HTML tags
    name = request.args.get("name", "User")
    return f"Hello {name}"  # No HTML tags in constant part, should be safe from XSS analyzer

if __name__ == "__main__":
    app.run()
