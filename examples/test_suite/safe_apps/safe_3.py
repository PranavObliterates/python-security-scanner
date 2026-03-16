from flask import Flask
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = "correct_way_to_handle_secrets_is_env_vars"
csrf = CSRFProtect(app)

@app.route("/submit", methods=["POST"])
def submit():
    return "CSRF Protected"

if __name__ == "__main__":
    app.run()
