from flask import Flask, render_template, request, redirect, session
import sqlite3
import os
from dotenv import load_dotenv

# Загрузка переменных окружения
load_dotenv()

DB_PATH = os.getenv("DB_PATH")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")  # по умолчанию, если не указано

app = Flask(__name__)
app.secret_key = SECRET_KEY

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "admin":
            session["user"] = "admin"
            return redirect("/dashboard")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    conn = get_db_connection()
    tickets = conn.execute("SELECT * FROM tickets ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("dashboard.html", tickets=tickets)

@app.route("/create", methods=["GET", "POST"])
def create():
    if "user" not in session:
        return redirect("/")
    if request.method == "POST":
        sender = request.form["sender"]
        subject = request.form["subject"]
        body = request.form["body"]
        conn = get_db_connection()
        conn.execute("INSERT INTO tickets (sender, subject, body) VALUES (?, ?, ?)", (sender, subject, body))
        conn.commit()
        conn.close()
        return redirect("/dashboard")
    return render_template("create.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
