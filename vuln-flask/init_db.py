import sqlite3

conn = sqlite3.connect("vuln.db")
cursor = conn.cursor()

# Users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
)
""")

# Comments table (for Stored XSS)
cursor.execute("""
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT NOT NULL,
    body TEXT NOT NULL
)
""")

# Seed users
cursor.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [
    ("admin",  "supersecret123", "admin"),
    ("alice",  "password1",      "user"),
    ("bob",    "letmein",        "user"),
])

conn.commit()
conn.close()
print("[+] Database initialized: vuln.db")
