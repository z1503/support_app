from flask import Flask, render_template, request, redirect, session, url_for, flash, send_from_directory, make_response
from flask_mail import Mail, Message
import sqlite3
import os
from dotenv import load_dotenv
from functools import wraps
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import decode_header
from datetime import datetime
import pytz
import json
from flask_login import login_required, current_user
from flask import abort
from flask import send_from_directory, Response
import mimetypes
import uuid
import magic

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)

# Загрузка переменных из .env
load_dotenv()

# Пути и секретные данные
DB_PATH = os.getenv("DB_PATH", "tickets.db")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")

# Инициализация Flask
app = Flask(__name__)
app.secret_key = SECRET_KEY  # Установка секретного ключа

# Конфигурация Flask-Mail
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "smtp.mail.ru")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 465))
app.config["MAIL_USE_SSL"] = os.getenv("MAIL_USE_SSL", "True") == "True"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")

# Настройки для загрузки файлов
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB лимит
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx', 'txt', 'zip'}
ALLOWED_MIME_TYPES = {'image/jpeg','image/png','application/pdf','application/vnd.openxmlformats-officedocument.wordprocessingml.document',}

# Инициализация Flask-Mail
mail = Mail(app)

def get_mime_type(file):
    file.seek(0)
    mime = magic.Magic(mime=True)
    mime_type = mime.from_buffer(file.read(2048))
    file.seek(0)
    return mime_type

def save_file(file):
    if file and allowed_file(file.filename):
        # Проверка MIME-типа (браузерный заголовок)
        if file.mimetype not in ALLOWED_MIME_TYPES:
            return None  # MIME-тип не разрешён

        filename = secure_filename(file.filename)
        ext = filename.rsplit('.', 1)[-1]
        unique_name = f"{uuid.uuid4().hex}.{ext}"
        upload_path = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_path):
            os.makedirs(upload_path)
        file.save(os.path.join(upload_path, unique_name))
        return unique_name
    return None

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

def decode_sender(encoded_sender):
    decoded_parts = decode_header(encoded_sender)
    decoded_str = ""
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            decoded_str += part.decode(encoding or "utf-8")
        else:
            decoded_str += part
    return decoded_str

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

@app.template_filter('decode_mime')
def decode_mime_string(mime_string):
    decoded_bytes, encoding = decode_header(mime_string)[0]
    if isinstance(decoded_bytes, bytes):
        return decoded_bytes.decode(encoding if encoding else 'utf-8')
    return decoded_bytes

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403

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
            session["user_id"] = user["id"]
            session["user"] = user["username"]
            session["role"] = user["role"]
            session["user_avatar"] = user["avatar"] if user["avatar"] else "default_avatar.png"
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
    role = session.get("role")
    user_id = session.get("user_id")

    # Параметры запроса
    sort_by = request.args.get('sort_by', 'created_at')
    sort_order = request.args.get('sort_order', 'desc')
    status_filter = request.args.get('status_filter')
    page = int(request.args.get('page', 1))

    # Чтение параметра per_page из URL или cookies
    per_page = request.args.get('per_page', request.cookies.get('per_page', 20))  # по умолчанию 20 заявок
    per_page = int(per_page)

    # Ограничиваем значение per_page для предотвращения перегрузки
    if per_page > 100:
        per_page = 100  # Установите ограничение на 100 заявок на страницу

    valid_columns = ['id', 'sender', 'subject', 'status', 'created_at']
    if sort_by not in valid_columns:
        sort_by = 'created_at'

    query = """
        SELECT t.*, u.username AS assigned_username
        FROM tickets t
        LEFT JOIN users u ON t.assigned_to = u.id
    """
    params = []

    if role == "client":
        query += " WHERE t.user_id = ?"
        params.append(user_id)
    else:
        query += " WHERE 1=1"

    if status_filter:
        query += " AND t.status = ?"
        params.append(status_filter)

    # Для подсчета общего количества записей (без LIMIT)
    count_query = "SELECT COUNT(*) FROM (" + query + ") as total"
    total_tickets = conn.execute(count_query, params).fetchone()[0]

    # Пагинация
    offset = (page - 1) * per_page
    query += f" ORDER BY {sort_by} {sort_order} LIMIT {per_page} OFFSET {offset}"

    tickets = conn.execute(query, params).fetchall()
    conn.close()

    total_pages = (total_tickets + per_page - 1) // per_page  # округление вверх

    # Сохранение выбора per_page в cookies
    resp = make_response(render_template(
        "dashboard.html",
        tickets=tickets,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        status_filter=status_filter
    ))
    resp.set_cookie('per_page', str(per_page), max_age=60*60*24*30)  # Сохраняем на 30 дней
    return resp

@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()
        user_id = session.get("user_id")
        sender = session.get("user")
        status = "новая"

        if not subject or not body:
            flash("Все поля должны быть заполнены", "danger")
            return redirect(url_for("create"))

        # Часовой пояс Москвы
        moscow_tz = pytz.timezone('Europe/Moscow')
        created_at = datetime.now(moscow_tz).strftime('%Y-%m-%d %H:%M:%S')

        # --- Безопасная работа с файлами ---
        attachment = []
        files = request.files.getlist("files[]")  # Получаем список всех файлов

        for file in files:
            if file and file.filename:
                filename = save_file(file)
                if filename:
                    attachment.append(filename)
                else:
                    flash("Неподдерживаемый формат файла или MIME-типа. Разрешены: jpg, jpeg, png, pdf, docx, txt", "danger")
                    return redirect(url_for("create"))
        # --- Конец блока загрузки файлов ---

        # Преобразуем список файлов в строку, разделённую запятой
        attachment_str = ",".join(attachment) if attachment else None

        # Сохранение заявки в базу данных
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO tickets (sender, subject, body, status, user_id, created_at, attachment) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sender, subject, body, status, user_id, created_at, attachment_str)
        )
        conn.commit()
        conn.close()

        flash("Заявка успешно создана", "success")
        return redirect(url_for("dashboard"))

    return render_template("create.html")


@app.route("/ticket/<int:ticket_id>", methods=["GET", "POST"])
@login_required
def ticket(ticket_id):
    # Используем контекстный менеджер для работы с БД
    with get_db_connection() as conn:
        ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()

        # Если заявка не найдена
        if ticket is None:
            flash("Заявка не найдена.", "error")
            return redirect(url_for('dashboard'))

        users = conn.execute("SELECT id, username FROM users WHERE role IN ('admin', 'user')").fetchall()

        # Преобразуем ticket в обычный словарь, чтобы можно было модифицировать
        ticket_dict = dict(ticket)

        # Декодируем данные, если нужно (например, заголовки письма)
        ticket_dict["sender"] = decode_sender(ticket_dict["sender"])
        ticket_dict["subject"] = decode_sender(ticket_dict["subject"])

        # Преобразуем строку в datetime объект для правильного отображения
        ticket_dict["created_at"] = datetime.strptime(ticket_dict["created_at"], "%Y-%m-%d %H:%M:%S")

        # Если необходимо, форматируем дату в более удобочитаемый вид
        ticket_dict["created_at_display"] = ticket_dict["created_at"].strftime("%d-%m-%Y %H:%M:%S")

        # Обработка изменения статуса и назначения ответственного
        if request.method == "POST":
            status = request.form.get("status")
            assigned_to = request.form.get("assigned_to")

            if status:
                conn.execute("UPDATE tickets SET status = ? WHERE id = ?", (status, ticket_id))
            
            if assigned_to:
                conn.execute("UPDATE tickets SET assigned_to = ? WHERE id = ?", (assigned_to, ticket_id))

            conn.commit()
            flash("Заявка обновлена.", "success")
            return redirect(url_for('ticket', ticket_id=ticket_id))

    # Передаем в шаблон обновленный ticket_dict
    return render_template("ticket.html", ticket=ticket_dict, users=users)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route('/admin_dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT status, COUNT(*) FROM tickets GROUP BY status")
    statuses = cursor.fetchall()

    status_labels = [s["status"] for s in statuses]
    status_counts = [s[1] for s in statuses]

    conn.close()

    return render_template('admin_dashboard.html', status_labels=status_labels, status_counts=status_counts)

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

@app.route("/admin/users/delete", methods=["POST"])
def delete_selected_users():
    try:
        conn = get_db_connection()

        # Получаем список ID пользователей, которых нужно удалить
        user_ids = request.form.getlist('user_ids')  # Получаем список ID пользователей

        if not user_ids:
            flash("Не выбраны пользователи для удаления", "error")
            return redirect(url_for('admin_users'))

        # Проверяем, сколько администраторов осталось после удаления
        for user_id in user_ids:
            user = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()

            if user and user["role"] == "admin":
                admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
                if admin_count <= 1:
                    conn.close()
                    flash("Нельзя удалить последнего администратора!", "error")
                    return redirect(url_for('admin_users'))

        # Удаляем выбранных пользователей
        conn.execute("DELETE FROM users WHERE id IN ({})".format(','.join(['?']*len(user_ids))), tuple(user_ids))
        conn.commit()
        conn.close()

        flash("Выбранные пользователи успешно удалены", "success")
        return redirect(url_for('admin_users'))
    except Exception as e:
        app.logger.error(f"Error during users deletion: {e}")
        flash("Ошибка при удалении пользователей", "error")
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

@app.route('/profile', methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()

    if request.method == "POST":
        # Если нажали кнопку удалить фото
        if 'delete_avatar' in request.form:
            avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], user['avatar'])
            
            # Проверяем, что фото существует, и удаляем его (кроме дефолтного)
            if user['avatar'] and user['avatar'] != 'default_avatar.png' and os.path.exists(avatar_path):
                os.remove(avatar_path)

            # Обновляем поле аватара в базе данных на default_avatar.png
            conn = get_db_connection()
            conn.execute("UPDATE users SET avatar = ? WHERE id = ?", ('default_avatar.png', session['user_id']))
            conn.commit()
            conn.close()

            # Обновляем данные сессии
            session['user_avatar'] = 'default_avatar.png'

            flash("Фото успешно удалено", "success")
            return redirect(url_for('profile'))

        # Обработка загрузки нового аватара
        if 'avatar' in request.files:
            avatar = request.files['avatar']
            if avatar and avatar.filename:
                filename = save_file(avatar)
                if filename:
                    # Удаляем старый аватар, если он не дефолтный
                    old_avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], user['avatar'])
                    if user['avatar'] and user['avatar'] != 'default_avatar.png' and os.path.exists(old_avatar_path):
                        os.remove(old_avatar_path)

                    # Обновляем информацию о пользователе в базе данных
                    conn = get_db_connection()
                    conn.execute("UPDATE users SET avatar = ? WHERE id = ?", (filename, session['user_id']))
                    conn.commit()
                    conn.close()

                    # Обновляем данные сессии
                    session['user_avatar'] = filename

                    flash("Фото обновлено", "success")
                    return redirect(url_for('profile'))
                else:
                    flash("Неподдерживаемый формат файла или MIME-типа для аватара.", "danger")
                    return redirect(url_for('profile'))

        # Обработка других данных (email и пароля)
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password and password != confirm_password:
            error = "Пароли не совпадают"
            return render_template("profile.html", user=user, error=error)

        if password:
            hashed_password = generate_password_hash(password)
            conn = get_db_connection()
            conn.execute("UPDATE users SET email = ?, password = ? WHERE id = ?",
                         (email, hashed_password, session['user_id']))
            conn.commit()
            conn.close()
        else:
            # Обновляем email в базе данных
            conn = get_db_connection()
            conn.execute("UPDATE users SET email = ? WHERE id = ?", (email, session['user_id']))
            conn.commit()
            conn.close()

        # Обновляем данные в сессии
        session['user_email'] = email

        flash("Данные обновлены", "success")
        return redirect(url_for('profile'))

    return render_template("profile.html", user=user)

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    flash("Файл слишком большой. Максимальный размер — 16 МБ.", "danger")
    return redirect(request.url)

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

@app.route("/admin/users/edit/<int:user_id>", methods=["GET", "POST"])
def edit_user(user_id):
    try:
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

        if not user:
            flash("Пользователь не найден", "error")
            return redirect(url_for('admin_users'))

        if request.method == "POST":
            username = request.form["username"]
            email = request.form["email"]
            role = request.form["role"]
            password = request.form["password"]

            # Если пароль был изменён, то хешируем новый пароль
            if password:
                password_hash = generate_password_hash(password)
                conn.execute("UPDATE users SET username = ?, email = ?, role = ?, password = ? WHERE id = ?",
                             (username, email, role, password_hash, user_id))
            else:
                conn.execute("UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
                             (username, email, role, user_id))

            conn.commit()
            # Получаем обновлённые данные пользователя
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            conn.close()
            flash("Данные пользователя успешно обновлены", "success")
            # Остаёмся на этой же странице
            return render_template('edit_user.html', user=user)

        conn.close()
        return render_template('edit_user.html', user=user)

    except Exception as e:
        app.logger.error(f"Error during user update: {e}")
        flash("Ошибка при обновлении данных пользователя", "error")
        return redirect(url_for('admin_users'))


@app.route("/admin/users/create_user", methods=["POST"])
def create_user():
    username = request.form["username"]
    email = request.form["email"]
    role = request.form["role"]
    password = request.form["password"]

    if not username or not email or not role or not password:
        flash("Все поля обязательны", "error")
        return redirect(url_for('admin_users'))

    try:
        password_hash = generate_password_hash(password)
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO users (username, email, role, password) VALUES (?, ?, ?, ?)",
            (username, email, role, password_hash)
        )
        conn.commit()
        conn.close()
        flash("Пользователь успешно создан", "success")
    except Exception as e:
        app.logger.error(f"Ошибка при создании пользователя: {e}")
        flash("Ошибка при создании пользователя", "error")

    return redirect(url_for('admin_users'))

@app.route("/delete_selected_tickets", methods=["POST"])
@login_required
def delete_selected_tickets():
    if "ticket_ids" not in request.form:
        flash("Выберите заявки для удаления", "error")
        return redirect(url_for("dashboard"))

    ticket_ids = request.form.getlist("ticket_ids")

    try:
        conn = get_db_connection()
        for ticket_id in ticket_ids:
            # Только свои заявки можно удалять, если не admin
            if session.get("role") != "admin":
                ticket = conn.execute("SELECT user_id FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
                if not ticket or ticket["user_id"] != session["user_id"]:
                    continue
            conn.execute("DELETE FROM tickets WHERE id = ?", (ticket_id,))
        conn.commit()
        conn.close()
        flash("Выбранные заявки удалены", "success")
    except Exception as e:
        app.logger.error(f"Ошибка при удалении заявок: {e}")
        flash("Ошибка при удалении заявок", "error")

    return redirect(url_for("dashboard"))

@app.route("/ticket/delete/<int:ticket_id>", methods=["POST"])
@login_required
def delete_ticket(ticket_id):
    conn = get_db_connection()

    # Проверка: если роль клиента, он не может удалять заявки
    if session["role"] == "client":
        flash("У вас нет прав для удаления заявки", "error")
        conn.close()
        return redirect(url_for("dashboard"))

    conn.execute("DELETE FROM tickets WHERE id = ?", (ticket_id,))
    conn.commit()
    conn.close()
    flash("Заявка удалена", "success")
    return redirect(url_for("dashboard"))

@app.route("/create_public", methods=["GET", "POST"])
def create_public_ticket():
    if request.method == "POST":
        sender = request.form.get("sender")
        subject = request.form.get("subject")
        body = request.form.get("body")

        if not sender or not subject or not body:
            flash("Пожалуйста, заполните все поля.", "danger")
            return redirect(url_for("create_public_ticket"))

        # --- Безопасная обработка вложений ---
        attachments = []
        files = request.files.getlist("files")  # Получаем список файлов
        for file in files:
            if file and file.filename:  # Если файл выбран
                filename = save_file(file)
                if filename:
                    attachments.append(filename)
                else:
                    flash("Неподдерживаемый формат файла или MIME-типа. Допустимые форматы: jpg, jpeg, png, pdf, docx, txt", "danger")
                    return redirect(url_for("create_public_ticket"))
        # --- Конец блока загрузки файлов ---

        # Если вложений несколько, то сохраняем их как строку, разделённую запятой
        attachment_str = ','.join(attachments) if attachments else None

        # Время в часовом поясе Москвы
        moscow_tz = pytz.timezone('Europe/Moscow')
        created_at = datetime.now(moscow_tz).strftime('%Y-%m-%d %H:%M:%S')

        # Сохранение заявки в БД
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO tickets (sender, subject, body, attachment, status, created_at) VALUES (?, ?, ?, ?, 'новая', ?)",
            (sender, subject, body, attachment_str, created_at)
        )
        ticket_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return redirect(url_for('thank_you', ticket_id=ticket_id))

    return render_template("create_public_ticket.html")


@app.route("/thank_you/<int:ticket_id>")
def thank_you(ticket_id):
    return render_template("thank_you.html", ticket_id=ticket_id)

@app.route("/confirm")
def confirm_email():
    email = request.args.get("email")
    if not email:
        flash("Некорректная ссылка подтверждения.", "danger")
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        conn.close()
        flash("Пользователь не найден.", "danger")
        return redirect(url_for("login"))

    if user["is_confirmed"]:
        conn.close()
        flash("Email уже подтвержден.", "info")
        return redirect(url_for("login"))

    # Обновляем флаг подтверждения
    conn.execute("UPDATE users SET is_confirmed = 1 WHERE email = ?", (email,))
    conn.commit()
    conn.close()

    flash("Email успешно подтвержден! Теперь вы можете войти.", "success")
    return redirect(url_for("login"))

@app.route('/uploads/<filename>')
@login_required  # если только для авторизованных пользователей
def uploaded_file(filename):
    # Защита от path traversal
    if '/' in filename or '..' in filename:
        abort(400)

    # Проверка прав доступа:
    # 1. Если это аватар - только владелец или админ
    # 2. Если это вложение тикета - только автор тикета, исполнитель или админ

    user_id = session.get("user_id")
    user_role = session.get("role")

    # Проверка, что файл - аватар текущего пользователя
    if filename == session.get("user_avatar"):
        pass  # разрешаем

    # Проверка, что пользователь - админ
    elif user_role == "admin":
        pass  # разрешаем

    # Проверка, что файл - вложение к тикету пользователя (пример)
    else:
        conn = get_db_connection()
        ticket = conn.execute(
            "SELECT * FROM tickets WHERE (user_id = ? OR assignee_id = ?) AND (attachment LIKE ? OR attachment LIKE ? OR attachment LIKE ? OR attachment = ?)",
            (user_id, user_id, f"{filename},%", f"%,{filename},%", f"%,{filename}", filename)
        ).fetchone()
        conn.close()
        if not ticket:
            abort(403)

    # Проверяем, что файл действительно существует
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        abort(404)

    # Определяем MIME-тип
    mime_type, _ = mimetypes.guess_type(file_path)

    # Отдаём файл с корректным MIME-типом
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, mimetype=mime_type)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        logging.error("No file part")
        return 'No file part'

    file = request.files['file']
    
    if file.filename == '':
        logging.error("No selected file")
        return 'No selected file'
    
    filename = save_file(file)
    if filename:
        logging.info(f"File {filename} saved to {app.config['UPLOAD_FOLDER']}")
        # Обновляем путь к аватару в сессии
        session['user_avatar'] = filename
        return redirect(url_for('profile'))  # Перенаправление на страницу профиля
    else:
        logging.error("File type or MIME-type not allowed")
        # Лучше использовать flash-сообщение для пользователя:
        flash("Неподдерживаемый формат файла или MIME-типа для аватара.", "danger")
        return redirect(url_for('profile'))


@app.route('/delete_avatar', methods=['POST'])
def delete_avatar():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute("SELECT avatar FROM users WHERE id = ?", (user_id,)).fetchone()

    if user and user['avatar'] and user['avatar'] != 'default_avatar.png':
        avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], user['avatar'])
        if os.path.exists(avatar_path):
            os.remove(avatar_path)  # удаляем файл
        # обновляем в БД
        conn.execute("UPDATE users SET avatar = ? WHERE id = ?", ('default_avatar.png', user_id))
        conn.commit()
        session['user_avatar'] = 'default_avatar.png'
    
    conn.close()
    flash('Аватар удалён', 'success')
    return redirect(url_for('profile'))

@app.route('/test-email')
def test_email_confirmation():
    return render_template(
        'email_confirmation.html',
        username="Тестовый пользователь",
        confirm_url="https://example.com/confirm/abc123"
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
