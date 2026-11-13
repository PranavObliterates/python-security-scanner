"""Vulnerable FastAPI application — demonstrates common OWASP vulnerabilities.

Used for security scanner testing and evaluation benchmarks.

Usage:
    from examples.vulnerable_fastapi_app import app
    from security_scanner import scan_app
    result = scan_app(app, dynamic=False)
"""
import os
import sqlite3
import requests
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import HTMLResponse

# VULN: Debug mode enabled in production
app = FastAPI(title="VulnerableFastAPIApp", debug=True)

# VULN: CORS Wildcard combined with credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/user")
def get_user_vuln(user_id: str):
    """VULN: SQL Injection via f-string interpolation."""
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    rows = cur.fetchall()
    conn.close()
    return {"data": rows}


@app.get("/search", response_class=HTMLResponse)
def search_vuln(q: str):
    """VULN: Reflected XSS without output escaping."""
    return f"<h1>Search Results: {q}</h1>"


@app.get("/read")
def read_file_vuln(filepath: str):
    """VULN: Path Traversal without validation."""
    with open(filepath, "r") as f:
        content = f.read()
    return {"content": content}


@app.get("/fetch")
def proxy_url_vuln(target: str):
    """VULN: Server-Side Request Forgery (SSRF)."""
    resp = requests.get(target)
    return {"status": resp.status_code, "body": resp.text[:100]}


@app.get("/system")
def system_exec_vuln(command: str):
    """VULN: Command Injection via shell execution."""
    os.system(command)
    return {"status": "executed"}
