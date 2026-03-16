from flask import Flask, request

app = Flask(__name__)

@app.route("/comment", methods=["POST"])
def add_comment():
    comment = request.form.get("text")
    # VULN: XSS
    # VULN: CSRF (implicit on POST)
    return f"<div>Your comment: {comment}</div>"

@app.route("/config")
def show_config():
    # VULN: Hardcoded API key
    key = "ak_live_abcdef12345"
    return f"API Key: {key}"

if __name__ == "__main__":
    app.run(debug=True) # VULN: Debug
