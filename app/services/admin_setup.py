import secrets
from datetime import datetime, timedelta


def generate_admin_registration_link(db_connection):
    token = secrets.token_urlsafe(16)
    expiry = datetime.now() + timedelta(hours=1)

    cursor = db_connection.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM admin_token")
    except:
        cursor.execute(
            """
                CREATE TABLE admin_token (
                    token TEXT,
                    expiry DATETIME,
                    used YESNO
                )
            """
        )

    cursor.execute(
        "INSERT INTO admin_token (token, expiry, used) VALUES (?, ?, ?)",
        (token, expiry.strftime("%Y-%m-%d %H:%M:%S"), False),
    )

    db_connection.commit()

    print("[INFO] 🔐 Посилання для створення адміністратора (дійсне 1 година):")
    print(f"http://127.0.0.1:5000/admin-register/{token}")


def check_and_generate_admin_link(db_connection):
    try:
        cursor = db_connection.cursor()
        cursor.execute("SELECT id FROM users WHERE position = 'admin'")
        if not cursor.fetchone():
            generate_admin_registration_link(db_connection)
        else:
            print("[INFO] Адміністратор уже існує. Спецпосилання не потрібно.")
    except Exception as e:
        print(f"[ERROR] Не вдалося перевірити наявність адміністратора: {e}")
