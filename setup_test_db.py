"""Create test.db with sample data for run_flask_scan.py demonstrations."""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "test.db")


def setup_database():
    """Create the test database with a users table and sample rows."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    """)

    # Insert sample data (only if empty)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        sample_users = [
            (1, "alice", "alice_pass_123", "alice@example.com", "admin"),
            (2, "bob", "bob_secure_456", "bob@example.com", "user"),
            (3, "charlie", "charlie_789", "charlie@example.com", "user"),
            (4, "diana", "diana_pass_000", "diana@example.com", "editor"),
            (5, "eve", "eve_secret_111", "eve@example.com", "user"),
        ]
        cursor.executemany(
            "INSERT INTO users (id, username, password, email, role) VALUES (?, ?, ?, ?, ?)",
            sample_users,
        )
        print(f"  [+] Inserted {len(sample_users)} sample users")

    conn.commit()
    conn.close()
    print(f"  [+] Database ready at: {DB_PATH}")


if __name__ == "__main__":
    setup_database()
