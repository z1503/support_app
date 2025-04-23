from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os
from dotenv import load_dotenv
from functools import wraps
import logging
from werkzeug.security import generate_password_hash, check_password_hash

logging.basicConfig(level=logging.DEBUG)
load_dotenv()

DB_PATH = os.getenv("DB_PATH", "tickets.db")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")

app = Flask(__name__)
app.secret_key = SECRET_KEY

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "role" not in session or session["role"] != role:
                return redirect("/dashboard")
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route("/")
def index():
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user"] = user["username"]
            session["role"] = user["role"]
            return redirect("/dashboard")
        else:
            return "Неверный email или пароль", 401

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]
        hashed_password = generate_password_hash(password)

        try:
            conn = get_db_connection()
            conn.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                         (username, email, hashed_password, role))
            conn.commit()
            conn.close()
            return redirect("/login")
        except Exception as e:
            app.logger.error(f"Error during registration: {e}")
            return "Ошибка при регистрации", 500

    return render_template("register.html")

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db_connection()
    tickets = conn.execute("SELECT id, sender, subject, status, created_at FROM tickets ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("dashboard.html", tickets=tickets)

@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
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

@app.route("/ticket/<int:ticket_id>", methods=["GET", "POST"])
@login_required
def view_ticket(ticket_id):
    conn = get_db_connection()
    ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()

    if not ticket:
        conn.close()
        return "Заявка не найдена", 404

    if request.method == "POST":
        new_status = request.form["status"]
        conn.execute("UPDATE tickets SET status = ? WHERE id = ?", (new_status, ticket_id))
        conn.commit()
        conn.close()
        return redirect(url_for("dashboard"))

    conn.close()
    return render_template("ticket.html", ticket=ticket)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/admin_dashboard")
@login_required
@role_required("admin")
def admin_dashboard():
    return render_template("admin_dashboard.html")

@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_users():
    search_query = request.args.get("q", "")
    conn = get_db_connection()

    if search_query:
        users = conn.execute("""
            SELECT * FROM users
            WHERE username LIKE ? OR email LIKE ?
        """, (f"%{search_query}%", f"%{search_query}%")).fetchall()
    else:
        users = conn.execute("SELECT * FROM users").fetchall()

    conn.close()
    return render_template("admin_users.html", users=users, search_query=search_query)

@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@login_required
@role_required("admin")
def delete_user(user_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@login_required
@role_required("admin")
def update_user_role(user_id):
    new_role = request.form["role"]
    try:
        conn = get_db_connection()
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        conn.close()
        return redirect(url_for('admin_users'))
    except Exception as e:
        app.logger.error(f"Error updating user role: {e}")
        return "Ошибка при обновлении роли", 500

@app.route("/admin/users/<int:user_id>/update", methods=["POST"])
@login_required
@role_required("admin")
def update_user_info(user_id):
    username = request.form["username"]
    email = request.form["email"]
    role = request.form["role"]
    try:
        conn = get_db_connection()
        conn.execute("UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
                     (username, email, role, user_id))
        conn.commit()
        conn.close()
        return redirect(url_for('admin_users'))
    except Exception as e:
        app.logger.error(f"Error updating user info: {e}")
        return "Ошибка при обновлении данных пользователя", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
