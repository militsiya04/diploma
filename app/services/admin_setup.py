import secrets
from datetime import datetime, timedelta

import pyodbc


def generate_registration_link(
    db_connection: pyodbc.Connection,
    role: str,
    hours_valid: int = 1,
    base_url: str = "http://127.0.0.1:5000",
) -> str:
    token = secrets.token_urlsafe(16)
    expiry = datetime.now() + timedelta(hours=hours_valid)

    cursor = db_connection.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM registration_tokens")
    except (Exception,):
        cursor.execute(
            """
                CREATE TABLE registration_tokens (
                    token TEXT,
                    expiry DATETIME,
                    used YESNO,
                    role TEXT
                )
            """
        )

    cursor.execute(
        "INSERT INTO registration_tokens (token, expiry, used, role) VALUES (?, ?, ?, ?)",
        (token, expiry.strftime("%Y-%m-%d %H:%M:%S"), False, role),
    )

    db_connection.commit()

    full_url: str = f"{base_url}/register/{token}"
    print(f"[INFO] 🔐 Посилання для створення {role} (дійсне {hours_valid} год.):")
    print(full_url)
    return full_url


def check_and_generate_admin_link(db_connection: pyodbc.Connection) -> None:
    try:
        cursor: pyodbc.Cursor = db_connection.cursor()
        cursor.execute("SELECT id FROM users WHERE position = 'admin'")
        if not cursor.fetchone():
            generate_registration_link(db_connection, "admin")
        else:
            print("[INFO] Адміністратор уже існує. Спецпосилання не потрібно.")
    except Exception as e:
        print(f"[ERROR] Не вдалося перевірити наявність адміністратора: {e}")
