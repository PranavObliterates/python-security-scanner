"""Safe FastAPI application — demonstrates security best practices.

Scanner should produce ZERO code-level vulnerability findings.

Usage:
    from examples.safe_fastapi_app import app
    from security_scanner import scan_app
    result = scan_app(app, dynamic=False)
"""
import os
import sqlite3
import html
from fastapi import FastAPI, Query
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import HTMLResponse

app = FastAPI(title="SafeFastAPIApp", debug=False)

# SAFE: Explicit allowed origins (no wildcard with credentials)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted-dashboard.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/")
def index():
    return {"status": "ok", "service": "Safe FastAPI Service"}


@app.get("/user")
def get_user(user_id: int = Query(...)):
    """SAFE: Parameterized database query."""
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INT, name TEXT)")
    cur.execute("SELECT name FROM users WHERE id = ?", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return {"user": rows}


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    """SAFE: HTML escaped reflection to prevent XSS."""
    safe_q = html.escape(q)
    return f"<h1>Search results for: {safe_q}</h1>"


@app.get("/download")
def download_report(filename: str):
    """SAFE: Path traversal prevention via basename/directory restriction."""
    from werkzeug.utils import secure_filename
    safe_name = secure_filename(filename)
    base_dir = "/var/reports"
    full_path = os.path.join(base_dir, safe_name)
    return {"file_target": full_path}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
