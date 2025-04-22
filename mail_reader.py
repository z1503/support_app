import imaplib
import email
from email.header import decode_header
import sqlite3
import logging
import os

# Путь к папке с проектом
project_dir = "/home/zhr/support_app"
log_path = os.path.join(project_dir, "mail_reader.log")

# Настройки логирования
logging.basicConfig(filename=log_path, level=logging.INFO, format="%(asctime)s - %(message)s")

# Настройки Mail.ru
IMAP_SERVER = 'imap.mail.ru'
EMAIL_ACCOUNT = 'zahar.z1503@list.ru'
PASSWORD = 'mDbmXgrWgrXBiBzQLBhu'

def connect_and_read():
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ACCOUNT, PASSWORD)
        mail.select("inbox")

        status, messages = mail.search(None, '(UNSEEN)')
        if status != 'OK':
            logging.info("Нет новых писем.")
            return

        for num in messages[0].split():
            status, msg_data = mail.fetch(num, '(RFC822)')
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding or "utf-8")
                    from_ = msg.get("From")

                    # Расшифруем имя отправителя, если оно закодировано
                    name, addr = email.utils.parseaddr(from_)
                    name_decoded, enc = decode_header(name)[0]
                    if isinstance(name_decoded, bytes):
                        name_decoded = name_decoded.decode(enc or "utf-8")
                    from_ = f"{name_decoded} <{addr}>"

                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body = part.get_payload(decode=True).decode(errors='ignore')
                                break
                    else:
                        body = msg.get_payload(decode=True).decode(errors='ignore')

                    logging.info(f"Новое письмо от {from_} — {subject}")
                    save_ticket(subject, body)

        mail.logout()
    except Exception as e:
        logging.error(f"Ошибка: {str(e)}")

def save_ticket(title, description):
    conn = sqlite3.connect("/home/zhr/support_app/support.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            description TEXT,
            user_id INTEGER
        )
    ''')
    c.execute("INSERT INTO tickets (title, description, user_id) VALUES (?, ?, ?)", (title, description, 2))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    connect_and_read()
