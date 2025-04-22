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
            login TEXT(100),
            password TEXT(100),
            email TEXT(100),
            phone TEXT(100),
            first_name TEXT(100),
            surname TEXT(100),
            photo TEXT(100),
            position TEXT(100),
            info MEMO,
            age INTEGER
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
            pulse INTEGER,
            data DATETIME
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE dispersion (
            id COUNTER PRIMARY KEY,
            pulse INTEGER,
            data DATETIME
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE WaS (
            id COUNTER PRIMARY KEY,
            weight INTEGER,
            sugar TEXT(100)
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE pressure (
            id COUNTER PRIMARY KEY,
            bpressure INTEGER,
            apressure INTEGER
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
