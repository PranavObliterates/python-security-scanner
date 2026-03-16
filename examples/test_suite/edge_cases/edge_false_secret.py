from flask import Flask
import os

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()  # Won't trigger secret warning

@app.route("/info")
def info():
    # EDGE CASE: Variable has 'password' in name, but value is a description
    password_description = "A strong password should be 12 chars"
    return password_description

if __name__ == "__main__":
    app.run()
