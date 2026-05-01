from flask import Flask, render_template, request, jsonify
import sqlite3
from werkzeug.security import generate_password_hash
import re

app = Flask(__name__)

DB_NAME = "store.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def valid_email(email):
    pattern = r'^[^@]+@[^@]+\.[^@]+$'
    return re.match(pattern, email) is not None


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    full_name = data.get("full_name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    verify_password = data.get("verify_password", "")

    if not full_name or not email or not password or not verify_password:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    if not valid_email(email):
        return jsonify({"success": False, "message": "Invalid email address."}), 400

    if password != verify_password:
        return jsonify({"success": False, "message": "Passwords do not match."}), 400

    if len(password) < 8:
        return jsonify({"success": False, "message": "Password must be at least 8 characters."}), 400

    password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO users (full_name, email, password_hash)
            VALUES (?, ?, ?)
        """, (full_name, email, password_hash))

        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Account created successfully."}), 201

    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Email already exists."}), 400

    except Exception:
        return jsonify({"success": False, "message": "Server error."}), 500


if __name__ == "__main__":
    init_db()
    app.run(debug=True)