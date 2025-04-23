from flask import Flask, render_template, request, redirect, session, url_for
from flask_mail import Mail, Message
import sqlite3
import os
from dotenv import load_dotenv
from functools import wraps
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from flask import render_template
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from flask import flash, session

logging.basicConfig(level=logging.DEBUG)
load_dotenv()

DB_PATH = os.getenv("DB_PATH", "tickets.db")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Конфигурация Flask-Mail
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "smtp.mail.ru")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 465))
app.config["MAIL_USE_SSL"] = os.getenv("MAIL_USE_SSL", "True") == "True"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")

mail = Mail(app)

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

# Функция отправки письма с подтверждением
def send_confirmation_email(email, username="Пользователь"):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Подтверждение регистрации"
        msg["From"] = os.getenv("EMAIL_FROM")
        msg["To"] = email

        # Используем переменную окружения для домена
        domain_name = os.getenv("DOMAIN_NAME", "127.0.0.1:5000")  # если переменная не задана, по умолчанию localhost

        confirm_url = f"http://{domain_name}/confirm?email={email}"

        html = render_template("email_confirmation.html", username=username, confirm_url=confirm_url)
        msg.attach(MIMEText(html, "html"))

        # Используем переменные окружения для данных почтового ящика
        with smtplib.SMTP_SSL("smtp.mail.ru", 465) as server:
            server.login(os.getenv("EMAIL_FROM"), os.getenv("EMAIL_PASSWORD"))
            server.send_message(msg)

    except Exception as e:
        app.logger.error(f"Email sending failed: {e}")

@app.route("/")
def index():
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_or_email = request.form["username_or_email"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute("""
            SELECT * FROM users WHERE username = ? OR email = ?
        """, (username_or_email, username_or_email)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session['user_id'] = user['id']
            session["user"] = user["username"]
            session["role"] = user["role"]
            return redirect("/dashboard")
        else:
            return "Неверный логин или пароль", 401

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        hashed_password = generate_password_hash(password)

        try:
            conn = get_db_connection()

            # Проверяем, что email уникален
            user_exists_by_email = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user_exists_by_email:
                conn.close()
                return render_template("register.html", error="Пользователь с таким email уже существует.")

            # Проверяем, что имя пользователя уникально
            user_exists_by_username = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if user_exists_by_username:
                conn.close()
                return render_template("register.html", error="Пользователь с таким именем уже существует.")

            # Добавляем пользователя с ролью по умолчанию client
            conn.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                         (username, email, hashed_password, "client"))
            conn.commit()
            conn.close()

            flash("Регистрация прошла успешно!", "success")
            return redirect("/login")

        except Exception as e:
            app.logger.error(f"Error during registration: {e}")
            return "Ошибка при регистрации", 500

    return render_template("register.html")

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db_connection()

    if session["role"] == "client":
        # Показываем только заявки пользователя
        tickets = conn.execute(
            "SELECT id, sender, subject, status, created_at FROM tickets WHERE sender = ? ORDER BY created_at DESC",
            (session["user"],)
        ).fetchall()
    else:
        # Показываем все заявки
        tickets = conn.execute(
            "SELECT id, sender, subject, status, created_at FROM tickets ORDER BY created_at DESC"
        ).fetchall()

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
def delete_user(user_id):
    try:
        conn = get_db_connection()

        # Получаем роль пользователя, которого пытаемся удалить
        user = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()

        if not user:
            flash("Пользователь не найден", "error")
            conn.close()
            return redirect(url_for('admin_users'))

        # Если это админ, проверяем, сколько админов осталось
        if user and user["role"] == "admin":
            admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
            app.logger.debug(f"Trying to delete user_id={user_id}, role={user['role']}, remaining admins={admin_count}")
            if admin_count <= 1:
                conn.close()
                flash("Нельзя удалить последнего администратора!", "error")
                return redirect(url_for('admin_users'))

        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        flash("Пользователь успешно удалён", "success")
        return redirect(url_for('admin_users'))
    except Exception as e:
        app.logger.error(f"Error during user deletion: {e}")
        flash("Ошибка при удалении пользователя", "error")
        return redirect(url_for('admin_users'))

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

@app.route("/profile", methods=["GET", "POST"])
def profile():
    user_id = session.get('user_id')  # Получаем user_id из сессии

    if not user_id:
        return redirect("/login")  # Если user_id нет в сессии, перенаправляем на страницу входа

    # Дальше ваш код для редактирования профиля
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        return "Пользователь не найден", 404  # Если пользователь не найден, возвращаем ошибку

    # Обработка POST-запроса для редактирования данных профиля
    if request.method == "POST":
        new_email = request.form["email"]
        new_password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Проверяем, совпадают ли пароли
        if new_password != confirm_password:
            error_message = "Пароли не совпадают."
            return render_template("profile.html", error=error_message, user=user)

        try:
            # Проверяем, существует ли email в базе данных, кроме текущего пользователя
            user_with_email = conn.execute("SELECT * FROM users WHERE email = ? AND id != ?", (new_email, user_id)).fetchone()

            if user_with_email:
                error_message = "Пользователь с таким email уже существует."
                return render_template("profile.html", error=error_message, user=user)

            # Обновляем данные пользователя
            if new_password:
                hashed_password = generate_password_hash(new_password)
                conn.execute("UPDATE users SET email = ?, password = ? WHERE id = ?", (new_email, hashed_password, user_id))
            else:
                conn.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))

            conn.commit()
            conn.close()

            # После успешного обновления можно перенаправить на другую страницу, например на панель управления
            return redirect("/dashboard")

        except Exception as e:
            app.logger.error(f"Error during profile update: {e}")
            error_message = "Произошла ошибка при обновлении профиля."
            return render_template("profile.html", error=error_message, user=user)

    # Если метод GET, просто отображаем текущие данные пользователя
    conn.close()

    return render_template("profile.html", user=user)

@app.route("/update_role", methods=["POST"])
@login_required
def update_role():
    if session.get("role") != "admin":
        return "Доступ запрещён", 403

    user_id = request.form["user_id"]
    new_role = request.form["new_role"]

    try:
        conn = get_db_connection()
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        conn.close()
        return redirect("/admin/users")
    except Exception as e:
        app.logger.error(f"Ошибка при обновлении роли: {e}")
        return "Ошибка при обновлении роли", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
