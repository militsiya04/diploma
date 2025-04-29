import os
import time

import pyodbc
import win32com.client

DB_PATH = "./database/medical_system.accdb"


def create_access_db():
    access_app = win32com.client.Dispatch("Access.Application")
    try:
        try:
            access_app.CloseCurrentDatabase()
        except:
            pass

        access_app.NewCurrentDatabase(os.path.abspath(DB_PATH))
    finally:
        access_app.CloseCurrentDatabase()
        access_app.Quit()
        del access_app


def get_db_connection():
    conn_str = (
        r"DRIVER={Microsoft Access Driver (*.mdb, *.accdb)};"
        f"DBQ={os.path.abspath(DB_PATH)};"
    )
    return pyodbc.connect(conn_str)


def create_tables(conn):
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE calendar_events (
            id COUNTER PRIMARY KEY,
            patient_id INTEGER,
            title TEXT(100),
            start DATETIME,
            end DATETIME,
            description MEMO
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE users (
            id COUNTER PRIMARY KEY,
            login MEMO,
            password MEMO,
            email MEMO,
            phone MEMO,
            first_name MEMO,
            surname MEMO,
            photo MEMO,
            position MEMO,
            info MEMO,
            age INTEGER,
            phone_hash MEMO,
            email_hash MEMO
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE messages (
            id COUNTER PRIMARY KEY,
            sender_id INTEGER,
            receiver_id INTEGER,
            message MEMO,
            sent_at DATETIME,
            is_read INTEGER
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE pulse (
            id COUNTER PRIMARY KEY,
            user_id INTEGER,
            pulse INTEGER,
            date_when_created DATETIME
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE dispersion (
            id COUNTER PRIMARY KEY,
            user_id INTEGER,
            pulse INTEGER,
            date_when_created DATETIME
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE WaS (
            id COUNTER PRIMARY KEY,
            user_id INTEGER,
            weight INTEGER,
            sugar TEXT(100),
            date_when_created DATETIME
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE pressure (
            id COUNTER PRIMARY KEY,
            user_id INTEGER,
            bpressure INTEGER,
            apressure INTEGER,
            date_when_created DATETIME
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE otp_tokens (
            user_id INT,
            code TEXT,
            type TEXT,
            expiry DATETIME,
            used YESNO
        )
    """
    )

    cursor.execute("CREATE INDEX idx_calendar_events_patient_id ON calendar_events (patient_id)")
    cursor.execute("CREATE INDEX idx_messages_sender_id ON messages (sender_id)")
    cursor.execute("CREATE INDEX idx_messages_receiver_id ON messages (receiver_id)")
    cursor.execute("CREATE INDEX idx_pulse_user_id ON pulse (user_id)")
    cursor.execute("CREATE INDEX idx_dispersion_user_id ON dispersion (user_id)")
    cursor.execute("CREATE INDEX idx_WaS_user_id ON WaS (user_id)")
    cursor.execute("CREATE INDEX idx_pressure_user_id ON pressure (user_id)")
    cursor.execute("CREATE INDEX idx_otp_tokens_user_id ON otp_tokens (user_id)")

    cursor.execute(
        """
        ALTER TABLE calendar_events
        ADD CONSTRAINT fk_calendar_patient
        FOREIGN KEY (patient_id) REFERENCES users(id)
        """
    )

    cursor.execute(
        """
        ALTER TABLE messages
        ADD CONSTRAINT fk_messages_sender
        FOREIGN KEY (sender_id) REFERENCES users(id)
        """
    )

    cursor.execute(
        """
        ALTER TABLE messages
        ADD CONSTRAINT fk_messages_receiver
        FOREIGN KEY (receiver_id) REFERENCES users(id)
        """
    )

    cursor.execute(
        """
        ALTER TABLE pulse
        ADD CONSTRAINT fk_pulse_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        """
    )

    cursor.execute(
        """
        ALTER TABLE dispersion
        ADD CONSTRAINT fk_dispersion_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        """
    )

    cursor.execute(
        """
        ALTER TABLE WaS
        ADD CONSTRAINT fk_WaS_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        """
    )

    cursor.execute(
        """
        ALTER TABLE pressure
        ADD CONSTRAINT fk_pressure_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        """
    )

    cursor.execute(
        """
        ALTER TABLE otp_tokens
        ADD CONSTRAINT fk_otp_tokens_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        """
    )

    conn.commit()


def check_all_tables_exist(conn, required_tables):
    cursor = conn.cursor()
    existing_tables = [
        row.table_name.lower() for row in cursor.tables(tableType="TABLE")
    ]
    return all(table.lower() in existing_tables for table in required_tables)


def init_database():
    required_tables = [
        "calendar_events",
        "users",
        "messages",
        "pulse",
        "dispersion",
        "WaS",
        "pressure",
        "otp_tokens",
    ]

    if os.path.exists(DB_PATH):
        try:
            conn = get_db_connection()
            if check_all_tables_exist(conn, required_tables):
                print("[INFO] Усі таблиці існують. Нічого не робимо.")
                conn.close()
                return
            else:
                print("[WARN] Деякі таблиці відсутні. Перезаписуємо базу.")
                conn.close()
                os.remove(DB_PATH)
        except Exception as e:
            print(f"[ERROR] Неможливо підключитися до існуючої бази: {e}")
            os.remove(DB_PATH)

    print("[INFO] Створюємо нову базу...")
    create_access_db()

    timeout = 5
    while not os.path.exists(DB_PATH) and timeout > 0:
        time.sleep(0.5)
        timeout -= 0.5

    if not os.path.exists(DB_PATH):
        print("[ERROR] Файл бази так і не з’явився після створення.")
        return

    try:
        conn = get_db_connection()
        create_tables(conn)
        conn.close()
        print("[INFO] Базу даних створено і таблиці додано.")
    except Exception as e:
        print("[ERROR] Створено файл, але не вдалося створити таблиці.")
        print(e)
