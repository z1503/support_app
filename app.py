from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'secret_key_here'

DB_NAME = 'support.db'

# Инициализация базы данных
def init_db():
    if not os.path.exists(DB_NAME):
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL
                )
            ''')
            c.execute('''
                CREATE TABLE tickets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT DEFAULT 'Новая',
                    user_id INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')
            # Добавим тестового админа и пользователя
            c.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin', 'admin')")
            c.execute("INSERT INTO users (username, password, role) VALUES ('user', 'user', 'user')")
            conn.commit()

# Главная страница / логин
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
            user = c.fetchone()
            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[3]
                return redirect(url_for('dashboard'))
    return render_template('login.html')

# Панель
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        if session['role'] == 'admin':
            c.execute("SELECT tickets.id, title, description, status, username FROM tickets JOIN users ON tickets.user_id = users.id")
        else:
            c.execute("SELECT id, title, description, status FROM tickets WHERE user_id=?", (session['user_id'],))
        tickets = c.fetchall()
    return render_template('dashboard.html', tickets=tickets)

# Создание заявки
@app.route('/create', methods=['GET', 'POST'])
def create():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO tickets (title, description, user_id) VALUES (?, ?, ?)",
                      (title, description, session['user_id']))
            conn.commit()
        return redirect(url_for('dashboard'))
    return render_template('create.html')

# Изменение статуса (только для админа)
@app.route('/update/<int:ticket_id>', methods=['POST'])
def update(ticket_id):
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    new_status = request.form['status']
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("UPDATE tickets SET status=? WHERE id=?", (new_status, ticket_id))
        conn.commit()
    return redirect(url_for('dashboard'))

# Выход
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=5000)
