import imaplib
import email
from email.header import decode_header
import sqlite3
import logging
import os
from dotenv import load_dotenv

# Загружаем переменные из .env
load_dotenv()

EMAIL_ACCOUNT = os.getenv("EMAIL_ACCOUNT")
PASSWORD = os.getenv("EMAIL_PASSWORD")
IMAP_SERVER = os.getenv("IMAP_SERVER")
DB_PATH = os.getenv("DB_PATH")

# Настройка логирования
logging.basicConfig(
    filename=os.path.join(os.path.dirname(__file__), "mail_reader.log"),
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            subject TEXT,
            body TEXT,
            status TEXT DEFAULT 'open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def clean_text(text):
    return ''.join(c if c.isprintable() else '?' for c in text)

def check_mail():
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ACCOUNT, PASSWORD)
        mail.select("inbox")

        status, messages = mail.search(None, "UNSEEN")
        mail_ids = messages[0].split()

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        for mail_id in mail_ids:
            status, msg_data = mail.fetch(mail_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    
                    # Обработка темы
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding or "utf-8", errors="replace")
                    subject = clean_text(subject)

                    # Отправитель
                    from_ = msg.get("From")
                    from_ = clean_text(from_)

                    # Тело письма
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get("Content-Disposition"))

                            if content_type == "text/plain" and "attachment" not in content_disposition:
                                payload = part.get_payload(decode=True)
                                if payload:
                                    body = payload.decode(errors="replace")
                                    break
                    else:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            body = payload.decode(errors="replace")

                    body = clean_text(body)

                    cursor.execute("INSERT INTO tickets (sender, subject, body) VALUES (?, ?, ?)",
                                   (from_, subject, body))
                    conn.commit()

                    logging.info(f"Новое письмо от {from_} — {subject}")

        conn.close()
        mail.logout()

    except Exception as e:
        logging.error(f"Ошибка: {str(e)}")

if __name__ == "__main__":
    init_db()
    check_mail()
