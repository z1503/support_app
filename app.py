from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os
from dotenv import load_dotenv
from functools import wraps  # Нужно для login_required
import logging

logging.basicConfig(level=logging.DEBUG)
# Загрузка переменных окружения
load_dotenv()

DB_PATH = os.getenv("DB_PATH", "tickets.db")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")  # По умолчанию, если не указано

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Функция для подключения к базе данных
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Декоратор для проверки наличия пользователя в сессии
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function

# Главная страница (страница логина)
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "admin":
            session["user"] = "admin"
            return redirect("/dashboard")
    return render_template("login.html")

# Страница выхода
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

# Страница с заявками
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    try:
        conn = get_db_connection()
        tickets = conn.execute("SELECT id, sender, subject, created_at FROM tickets ORDER BY created_at DESC").fetchall()
        conn.close()
        return render_template("dashboard.html", tickets=tickets)
    except Exception as e:
        app.logger.error(f"Error occurred while fetching tickets: {e}")
        return "Ошибка при загрузке заявок", 500

# Страница создания заявки
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

# Просмотр заявки по ID
@app.route("/ticket/<int:ticket_id>", methods=["GET", "POST"])
@login_required
def view_ticket(ticket_id):
    conn = get_db_connection()
    ticket = conn.execute('SELECT * FROM tickets WHERE id = ?', (ticket_id,)).fetchone()

    if not ticket:
        conn.close()
        return 'Заявка не найдена', 404

    if request.method == 'POST':
        new_status = request.form['status']
        conn.execute('UPDATE tickets SET status = ? WHERE id = ?', (new_status, ticket_id))
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('ticket.html', ticket=ticket)

@app.route('/ticket/<int:ticket_id>/update', methods=['POST'])
@login_required
def update(ticket_id):
    new_status = request.form['status']
    conn = get_db_connection()
    conn.execute('UPDATE tickets SET status = ? WHERE id = ?', (new_status, ticket_id))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))


# Запуск приложения
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
