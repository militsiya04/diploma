import base64
import io
import os
import random
import re
import subprocess
from datetime import datetime
from io import BytesIO

import cv2
import numpy as np
import pandas as pd
from deepface import DeepFace
from docx import Document
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from reportlab.lib.pagesizes import letter
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from services.admin_setup import (
    check_and_generate_admin_link,
    generate_registration_link,
)
from services.captcha_generator import generate_captcha_image, generate_captcha_text
from services.document_reader import extract_text_from_docx, extract_text_from_pdf
from services.email_otp_service import configure_mail, send_otp_email
from services.init_database import get_db_connection, init_database
from services.send_sms import send_sms
from utils import (
    allowed_file,
    check_password,
    generate_session_token,
    hash_password,
    is_fully_authenticated,
    login_required_with_timeout,
    roles_required,
)
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "d9f9a8b7e5a4422aa1c8cf59d6d22e80"

UPLOAD_FOLDER = "uploads"
DATABASE_FOLDER = "database"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATABASE_FOLDER, exist_ok=True)

configure_mail(app)
init_database()
check_and_generate_admin_link(get_db_connection())


# ----- AUTHENTICATION CYCLE START -----
@app.route("/captcha")
def captcha():
    captcha_text = generate_captcha_text()
    session["captcha"] = captcha_text
    img_io = generate_captcha_image(captcha_text)
    return send_file(img_io, mimetype="image/png")


@app.route("/register/<token>", methods=["GET", "POST"])
def register_user(token: str):
    if is_fully_authenticated():
        return redirect(url_for("redirect_user"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT token, expiry, used, role FROM registration_tokens WHERE token = ?",
        (token,),
    )
    token_data = cursor.fetchone()

    if not token_data:
        return "⛔ Посилання недійсне або не існує.", 403
    if token_data[2]:
        return "⛔ Це посилання вже використано.", 403
    if datetime.now() > token_data[1]:
        return "⛔ Посилання протерміноване.", 403

    role = token_data[3]

    if role == "admin":
        cursor.execute("SELECT id FROM users WHERE position = 'admin'")
        if cursor.fetchone():
            conn.close()
            return (
                "⚠️ Адміністратор уже існує в системі. Повторна реєстрація неможлива.",
                403,
            )

    if request.method == "POST":
        login = request.form["login"]
        password = request.form["password"]
        email = request.form["email"]
        phone = request.form["phone"]
        first_name = request.form["first_name"]
        surname = request.form["surname"]
        user_captcha = request.form["captcha"].strip().lower()
        session_captcha = session.get("captcha", "").strip().lower()

        if user_captcha != session_captcha:
            flash("❌ Невірна капча!", "error")
            return redirect(request.url)

        session.pop("captcha", None)

        cursor.execute(
            """
            SELECT * FROM users 
            WHERE login = ? OR email = ? OR phone = ?
        """,
            (login, email, phone),
        )
        if cursor.fetchone():
            conn.close()
            flash(
                "❗ Користувач з таким логіном, email або телефоном уже існує!",
                "error",
            )
            return redirect(request.url)

        hashed_password = hash_password(password)
        cursor.execute(
            """
            INSERT INTO users (position, login, password, email, phone, first_name, surname)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (role, login, hashed_password, email, phone, first_name, surname),
        )

        cursor.execute(
            "UPDATE registration_tokens SET used = 1 WHERE token = ?", (token,)
        )
        conn.commit()
        conn.close()

        flash(f"✅ Користувач з роллю '{role}' успішно зареєстрований!", "success")
        return redirect(url_for("login"))

    return render_template("register.html", token=token, role=role)


@app.route("/", methods=["GET", "POST"])
def login():
    if is_fully_authenticated():
        return redirect(url_for("redirect_user"))

    if request.method == "POST":
        login = request.form["login"]
        password = request.form["password"]
        user_captcha = request.form["captcha"].strip().lower()
        session_captcha = session.get("captcha", "").strip().lower()

        if user_captcha != session_captcha:
            flash("Ошибка: Неверная капча!", "error")
            return redirect(url_for("login"))

        session.pop("captcha", None)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, position, first_name, email, phone, password FROM users WHERE login=?",
            (login,),
        )
        user = cursor.fetchone()
        conn.close()

        if user and check_password(password, user[5]):
            session["user_id"] = user[0]
            session["user_position"] = user[1]
            session["user_name"] = user[2]
            session["user_email"] = user[3]
            session["user_phone"] = user[4]
            return redirect(url_for("auth_options"))
        else:
            flash("Ошибка: Неверные данные!", "error")

    return render_template("login.html")


@app.route("/auth-options", methods=["GET", "POST"])
def auth_options():
    if is_fully_authenticated():
        return redirect(url_for("redirect_user"))
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("auth_options.html")


@app.route("/authenticate-email", methods=["POST"])
def authenticate_email():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if "user_email" not in session:
        flash("No email found.", "error")
        return redirect(url_for("auth_options"))

    send_otp_email(session["user_email"])
    return redirect(url_for("verify_email"))


@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    if is_fully_authenticated():
        return redirect(url_for("redirect_user"))
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        entered_otp = request.form["otp"]
        if "otp" in session and str(session["otp"]) == str(entered_otp):
            session.pop("otp", None)
            session["session_token"] = generate_session_token(
                session["user_id"], session["user_position"]
            )
            return redirect(url_for("redirect_user"))
        else:
            flash("Invalid OTP. Please try again.", "error")

    return render_template("verify_email.html")


@app.route("/authenticate-phone", methods=["POST"])
def authenticate_phone():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if "user_phone" not in session or not session["user_phone"]:
        flash("Ошибка: Телефон не найден.", "error")
        return redirect(url_for("auth_options"))
    return redirect(url_for("verify_phone"))


@app.route("/verify_phone", methods=["GET", "POST"])
def verify_phone():
    if request.method == "POST":
        entered_otp = request.form["otp"]
        actual_otp = session.get("phone_otp")

        if entered_otp == actual_otp:
            flash("Phone authentication successful!", "success")
            session["session_token"] = generate_session_token(
                session["user_id"], session["user_position"]
            )
            return redirect(url_for("redirect_user"))
        else:
            flash("Invalid OTP. Try again.", "error")
    else:
        # Генерация и отправка кода по SMS
        generated_code = "{:06d}".format(random.randint(0, 999999))
        session["phone_otp"] = generated_code

        phone_number = session.get("user_phone")
        if phone_number:
            message = f"Ваш код подтверждения: {generated_code}"
            result = send_sms([phone_number], message)

            if "error" in result:
                flash("Ошибка при отправке SMS: " + result["error"], "error")
            else:
                flash("Код отправлен на ваш номер телефона.", "info")
        else:
            flash("Номер телефона не найден в сессии.", "error")

    return render_template("verify_phone.html")


@app.route("/verify_face", methods=["GET", "POST"])
def verify_face():
    if request.method == "POST":
        user_id = session.get("user_id")
        if not user_id:
            flash("User ID not found in session", "error")
            return redirect(url_for("login"))

        photo_data = request.form.get("photo")
        if not photo_data:
            flash("Фото не получено", "error")
            return redirect(url_for("verify_face"))

        img_str = re.search(r"base64,(.*)", photo_data).group(1)
        img_bytes = base64.b64decode(img_str)
        np_arr = np.frombuffer(img_bytes, np.uint8)
        frame = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

        input_photo_path = f"patientphoto/temp_{user_id}.jpg"
        reference_photo_path = f"patientphoto/{user_id}.jpg"
        cv2.imwrite(input_photo_path, frame)

        if not os.path.exists(reference_photo_path):
            flash("Фото для сверки не найдено!", "error")
            os.remove(input_photo_path)
            return redirect(url_for("verify_face"))

        try:
            result = DeepFace.verify(
                img1_path=input_photo_path,
                img2_path=reference_photo_path,
                enforce_detection=True,
            )
            os.remove(input_photo_path)

            if result["verified"]:
                flash("✅ Биометрическая верификация прошла успешно!", "success")
                session["session_token"] = generate_session_token(
                    session["user_id"], session["user_position"]
                )
                return redirect(url_for("redirect_user"))
            else:
                flash("❌ Лицо не совпадает.", "error")
                return redirect(url_for("verify_face"))

        except Exception as e:
            flash(f"Ошибка сравнения: {str(e)}", "error")
            if os.path.exists(input_photo_path):
                os.remove(input_photo_path)
            return redirect(url_for("verify_face"))

    return render_template("verify_face.html")


@app.route("/redirect-user")
def redirect_user():
    if not is_fully_authenticated():
        return redirect(url_for("login"))

    if session["user_position"] == "patient":
        return redirect(url_for("dashboard"))
    elif session["user_position"] in ["doctor", "admin"]:
        return redirect(url_for("meddashboard"))

    flash("Ошибка: Неизвестная роль пользователя.", "error")
    return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ----- AUTHENTICATION CYCLE END -----


@app.route("/generate-links", methods=["GET", "POST"])
@login_required_with_timeout()
@roles_required("admin", "doctor")
def generate_links():
    conn = get_db_connection()
    cursor = conn.cursor()

    current_user_role = session["user_position"]
    allowed_roles = []

    if current_user_role == "admin":
        allowed_roles = ["doctor", "patient"]
    elif current_user_role == "doctor":
        allowed_roles = ["patient"]

    if request.method == "POST":
        selected_role = request.form.get("role")
        if selected_role not in allowed_roles:
            flash("❌ Ви не маєте прав створювати користувачів з цією роллю!", "error")
            return redirect(url_for("generate_links"))

        generate_registration_link(conn, selected_role, hours_valid=24)
        flash(f"✅ Посилання для {selected_role} згенеровано!", "success")
        return redirect(url_for("generate_links"))

    cursor.execute("""
        SELECT token, role, expiry
        FROM registration_tokens
        WHERE used = 0 AND expiry > ?
        ORDER BY expiry ASC
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))

    token_data = cursor.fetchall()
    conn.close()

    base_url = request.host_url.rstrip("/")
    tokens = [
        {
            "url": f"{base_url}/register/{row[0]}",
            "role": row[1],
            "expiry": row[2],
        }
        for row in token_data
    ]

    return render_template(
        "generate_links.html",
        allowed_roles=allowed_roles,
        tokens=tokens
    )


@app.route("/database", methods=["GET", "POST"])
@login_required_with_timeout()
@roles_required("admin", "doctor")
def database():
    if request.method == "POST":
        file = request.files.get("excel_file")
        table_choice = request.form.get("table_choice")  # "Pulse" или "Dispersion"

        if file and table_choice:
            try:
                df = pd.read_excel(file)
                df.columns = df.columns.str.lower()

                conn = get_db_connection()
                cursor = conn.cursor()

                if table_choice == "Pulse":
                    required_columns = {"id", "pulse", "data"}
                    if not required_columns.issubset(df.columns):
                        flash("❌ Pulse: потрібні стовпці: id, pulse, data", "error")
                        return redirect(url_for("database"))

                    cursor.execute("DELETE FROM pulse")
                    for _, row in df.iterrows():
                        cursor.execute(
                            "INSERT INTO pulse (id, pulse, data) VALUES (?, ?, ?)",
                            int(row["id"]),
                            int(row["pulse"]),
                            str(row["data"]),
                        )

                elif table_choice == "Dispersion":
                    required_columns = {"id", "pulse", "data"}
                    if not required_columns.issubset(df.columns):
                        flash(
                            "❌ Dispersion: потрібні стовпці: id, pulse, data", "error"
                        )
                        return redirect(url_for("database"))

                    cursor.execute("DELETE FROM dispersion")
                    for _, row in df.iterrows():
                        cursor.execute(
                            "INSERT INTO dispersion (id, pulse, data) VALUES (?, ?, ?)",
                            int(row["id"]),
                            int(row["pulse"]),
                            str(row["data"]),
                        )
                elif table_choice == "WaS":
                    required_columns = {"id", "weight", "sugar"}
                    if not required_columns.issubset(df.columns):
                        flash("❌ WaS: потрібні стовпці: id, weight, sugar", "error")
                        return redirect(url_for("database"))

                    cursor.execute("DELETE FROM WaS")
                    for _, row in df.iterrows():
                        cursor.execute(
                            "INSERT INTO WaS (id, weight, sugar) VALUES (?, ?, ?)",
                            int(row["id"]),
                            float(row["weight"]),
                            float(row["sugar"]),
                        )
                elif table_choice == "Pressure":
                    required_columns = {"id", "bpressure", "apressure"}
                    if not required_columns.issubset(df.columns.str.lower()):
                        flash(
                            "❌ Pressure: потрібні стовпці: id, bpressure, apressure",
                            "error",
                        )
                        return redirect(url_for("database"))

                    cursor.execute("DELETE FROM pressure")
                    for _, row in df.iterrows():
                        cursor.execute(
                            "INSERT INTO pressure (id, bpressure, apressure) VALUES (?, ?, ?)",
                            int(row["id"]),
                            int(row["bpressure"]),
                            int(row["apressure"]),
                        )

                conn.commit()
                conn.close()
                flash(f"✅ Дані імпортовано в таблицю {table_choice}!", "success")

            except Exception as e:
                flash(f"❌ Помилка імпорту: {e}", "error")

    return render_template("database.html")


@app.route("/export_selected")
@login_required_with_timeout()
@roles_required("admin", "doctor")
def export_selected():
    table_name = request.args.get("table")
    if table_name not in ["Pulse", "Dispersion", "WaS", "Pressure"]:
        flash("❌ Невідома таблиця для експорту.", "error")
        return redirect(url_for("database"))

    try:
        conn = get_db_connection()
        df = pd.read_sql(f"SELECT * FROM {table_name}", conn)
        conn.close()

        # Сохраняем Excel в память
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            df.to_excel(writer, index=False, sheet_name=table_name)

        output.seek(0)
        return send_file(
            output,
            as_attachment=True,
            download_name=f"{table_name.lower()}_data.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

    except Exception as e:
        flash(f"❌ Помилка експорту: {e}", "error")
        return redirect(url_for("database"))


@app.route("/dashboard")
@login_required_with_timeout()
@roles_required("patient")
def dashboard():
    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT position FROM users WHERE id = ?", (user_id,))
    position = cursor.fetchone()

    if not position:
        conn.close()
        flash("User not found.", "error")
        return redirect(url_for("login"))

    cursor.execute(
        "SELECT first_name, surname, phone, info, photo FROM users WHERE id = ?",
        (user_id,),
    )
    user = cursor.fetchone()

    patient_folder = os.path.join("patientexcels", str(user_id))
    files = os.listdir(patient_folder) if os.path.exists(patient_folder) else []

    conn.close()
    return render_template("dashboard.html", user=user, files=files)


@app.route("/download-info/<string:format>")
@login_required_with_timeout()
@roles_required("admin", "doctor")
def download_info(format):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT first_name, surname, email, phone, position, info FROM users WHERE id = ?",
        (session["user_id"],),
    )
    user = cursor.fetchone()
    conn.close()

    if not user:
        flash("User information not found.", "error")
        return redirect(url_for("dashboard"))

    if format == "pdf":
        font_path = r"/app/static/fonts/free-sans.ttf"
        pdfmetrics.registerFont(TTFont("FreeSans", font_path))

        pdf_file = BytesIO()
        c = canvas.Canvas(pdf_file, pagesize=letter)
        c.setFont("FreeSans", 12)

        c.drawString(100, 750, "Информация о пользователе")
        c.drawString(100, 730, f"Имя: {user[0]}")
        c.drawString(100, 710, f"Фамилия: {user[1]}")
        c.drawString(100, 690, f"Email: {user[2]}")
        c.drawString(100, 670, f"Телефон: {user[3]}")
        c.drawString(100, 650, f"Должность: {user[4] or 'N/A'}")
        c.drawString(100, 630, f"Информация: {user[5] or 'N/A'}")

        c.save()
        pdf_file.seek(0)

        return send_file(
            pdf_file,
            as_attachment=True,
            download_name="user_info.pdf",
            mimetype="application/pdf",
        )

    elif format == "docx":
        doc = Document()
        doc.add_heading("Информация о пользователе", level=1)
        doc.add_paragraph(f"Имя: {user[0]}")
        doc.add_paragraph(f"Фамилия: {user[1]}")
        doc.add_paragraph(f"Email: {user[2]}")
        doc.add_paragraph(f"Телефон: {user[3]}")
        doc.add_paragraph(f"Должность: {user[4] or 'N/A'}")
        doc.add_paragraph(f"Информация: {user[5] or 'N/A'}")

        doc_file = BytesIO()
        doc.save(doc_file)
        doc_file.seek(0)

        return send_file(
            doc_file,
            as_attachment=True,
            download_name="user_info.docx",
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )

    flash("Unsupported file format.", "error")
    return redirect(url_for("dashboard"))


@app.route("/inbox")
@login_required_with_timeout()
@roles_required("admin", "doctor")
def inbox():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT messages.id, users.first_name, users.surname, messages.message, messages.sent_at 
        FROM messages 
        INNER JOIN users ON messages.sender_id = users.id 
        WHERE messages.receiver_id = ? 
        ORDER BY messages.sent_at DESC
    """,
        (session["user_id"],),
    )
    messages = cursor.fetchall()

    conn.close()

    return render_template("inbox.html", messages=messages)


@app.route("/outbox")
@login_required_with_timeout()
@roles_required("admin", "doctor")
def outbox():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT messages.id, users.first_name, users.surname, messages.message, messages.sent_at 
        FROM messages 
        INNER JOIN users ON messages.receiver_id = users.id 
        WHERE messages.sender_id = ? 
        ORDER BY messages.sent_at DESC
    """,
        (session["user_id"],),
    )
    messages = cursor.fetchall()

    cursor.close()
    conn.close()
    return render_template("outbox.html", messages=messages)


@app.route("/send_message", methods=["GET", "POST"])
@login_required_with_timeout()
@roles_required("admin", "doctor")
def send_message():
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        sender_id = session["user_id"]
        receiver_id = request.form["receiver_id"]
        message = request.form["message"]

        query = (
            "INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)"
        )
        cursor.execute(query, (sender_id, receiver_id, message))
        conn.commit()

        cursor.close()
        conn.close()

        return redirect(url_for("outbox"))

    cursor.execute("SELECT id, first_name, surname FROM users")
    users = cursor.fetchall()

    cursor.close()
    conn.close()
    return render_template("send_message.html", users=users)


# Загрузка Excel-файла
@app.route("/upload-excel/<int:patient_id>", methods=["POST"])
@login_required_with_timeout()
@roles_required("admin", "doctor")
def upload_excel(patient_id):
    file = request.files.get("file")
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        patient_folder = os.path.join("patientexcels", str(patient_id))
        os.makedirs(patient_folder, exist_ok=True)

        filepath = os.path.join(patient_folder, filename)
        file.save(filepath)

        flash("Excel file uploaded successfully.", "success")
    else:
        flash("Invalid file format.", "error")

    return redirect(url_for("patient_dashboard", patient_id=patient_id))


@app.route("/edit_excel/<int:patient_id>/<filename>")
@login_required_with_timeout()
@roles_required("admin", "doctor")
def edit_excel(patient_id, filename):
    """
    Открывает страницу редактора и загружает данные из выбранного файла пациента.
    """
    patient_folder = os.path.join("patientexcels", str(patient_id))
    file_path = os.path.join(patient_folder, filename)

    if not os.path.exists(file_path):
        flash("Файл не найден.", "error")
        return redirect(url_for("patient_dashboard", patient_id=patient_id))

    try:
        df = pd.read_excel(file_path, engine="openpyxl", header=None)
        data = df.fillna("").values.tolist()
    except Exception as e:
        flash(f"Ошибка загрузки файла: {str(e)}", "error")
        return redirect(url_for("patient_dashboard", patient_id=patient_id))

    # Теперь возвращаем шаблон с данными
    return render_template(
        "edit_excel.html", patient_id=patient_id, filename=filename, table_data=data
    )


@app.route("/edit_excel/<int:patient_id>/<filename>/save", methods=["POST"])
@login_required_with_timeout()
@roles_required("admin", "doctor")
def save_excel(patient_id, filename):
    data = request.get_json().get("table_data")
    if not data:
        return jsonify({"message": "Немає даних для збереження"}), 400

    try:
        file_path = os.path.join("patientexcels", str(patient_id), filename)
        df = pd.DataFrame(data)
        df.to_excel(file_path, index=False, header=False, engine="openpyxl")
        return jsonify({"message": "Таблицю збережено успішно."})
    except Exception as e:
        return jsonify({"message": f"Помилка при збереженні: {str(e)}"}), 500


@app.route("/edit_excel/<int:patient_id>/<filename>/download", methods=["POST"])
@login_required_with_timeout()
@roles_required("admin", "doctor")
def download_excel(patient_id, filename):
    data = request.get_json().get("table_data")
    if not data:
        return "Немає даних для експорту", 400

    try:
        df = pd.DataFrame(data)
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, header=False)
        output.seek(0)

        return send_file(
            output,
            as_attachment=True,
            download_name="edited_table.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except Exception as e:
        return f"Помилка при створенні файлу: {str(e)}", 500


@app.route("/patients/<int:patient_id>/create_new_excel", methods=["POST"])
@login_required_with_timeout()
@roles_required("admin", "doctor")
def create_new_excel(patient_id):
    """Создает новый пустой Excel-файл для пациента."""
    data = request.json
    filename = data.get("filename", "new_table.xlsx")

    patient_folder = os.path.join("patientexcels", str(patient_id))
    os.makedirs(patient_folder, exist_ok=True)

    file_path = os.path.join(patient_folder, filename)

    try:
        df = pd.DataFrame([["", ""], ["", ""]])  # Пустая таблица
        df.to_excel(file_path, index=False, header=False, engine="openpyxl")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/calendar/<int:patient_id>", methods=["GET"])
@login_required_with_timeout()
@roles_required("admin", "doctor")
def get_calendar(patient_id):
    """Получает список событий пациента из базы Access."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, title, start, end, description FROM calendar_events WHERE patient_id = ?",
        (patient_id,),
    )
    events = cursor.fetchall()
    conn.close()

    formatted_events = [
        {
            "id": event.id,
            "title": event.title,
            "start": event.start.strftime("%Y-%m-%dT%H:%M") if event.start else None,
            "end": event.end.strftime("%Y-%m-%dT%H:%M") if event.end else None,
            "description": event.description,
        }
        for event in events
    ]

    return jsonify(formatted_events)


@app.route("/meddashboard", methods=["GET"])
@login_required_with_timeout()
@roles_required("admin", "doctor")
def meddashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Получаем параметры поиска и сортировки
    search_query = request.args.get("search", "").strip()
    sort_by = request.args.get("sort_by", "first_name")
    sort_order = request.args.get("sort_order", "ASC").upper()

    valid_sort_columns = ["first_name", "surname"]
    if sort_by not in valid_sort_columns:
        sort_by = "first_name"

    if sort_order not in ["ASC", "DESC"]:
        sort_order = "ASC"

    query = "SELECT id, first_name, surname, phone, email FROM users WHERE position = 'Пациент'"
    params = []

    if search_query:
        query += " AND first_name LIKE '*' || ? || '*'"
        params.append(search_query)

    query += f" ORDER BY {sort_by} {sort_order}"

    cursor.execute(query, params)
    patients = cursor.fetchall()
    conn.close()

    return render_template(
        "meddashboard.html",
        patients=patients,
        search_query=search_query,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@app.route("/patient/<int:patient_id>")
@login_required_with_timeout()
@roles_required("admin", "doctor")
def patient_dashboard(patient_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT first_name, surname, phone, info, photo FROM users WHERE id = ?",
            (patient_id,),
        )
        patient = cursor.fetchone()
        conn.close()

        if not patient:
            flash("Patient not found.", "error")
            return redirect(url_for("meddashboard"))

        # Находим файлы пациента
        patient_folder = os.path.join("patientexcels", str(patient_id))
        files = os.listdir(patient_folder) if os.path.exists(patient_folder) else []

        return render_template(
            "patient_dashboard.html",
            patient=patient,
            patient_id=patient_id,
            files=files,
        )

    except Exception as e:
        flash(f"Database error: {e}", "error")
        return redirect(url_for("dashboard"))


@app.route("/upload-document", methods=["POST"])
@login_required_with_timeout()
@roles_required("admin", "doctor")
def upload_document():
    file = request.files["file"]
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        # Чтение данных из документа
        if filename.endswith(".pdf"):
            text = extract_text_from_pdf(filepath)
        elif filename.endswith(".docx"):
            text = extract_text_from_docx(filepath)
        else:
            flash("Unsupported file format.", "error")
            return redirect(url_for("dashboard"))

        # Обновление информации о пользователе в MS Access
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET info = ? WHERE id = ?", (text, session["user_id"])
            )
            conn.commit()
        except Exception as e:
            flash(f"Database error: {str(e)}", "error")
        finally:
            conn.close()

        flash("Document uploaded and information updated successfully.", "success")
        return redirect(url_for("dashboard"))

    flash("No file selected.", "error")
    return redirect(url_for("dashboard"))


@app.route("/run-tkinter/<patient_id>", methods=["POST"])
@login_required_with_timeout()
@roles_required("admin", "doctor")
def run_tkinter(patient_id):
    path = r"C:\Users\User\Documents\diploma\app\patientexcels"
    patient_folder = os.path.join(path, patient_id)

    if not os.path.exists(patient_folder):
        return "Ошибка: папка пациента не найдена!", 400

    # Запускаем Tkinter и передаём ID пациента как аргумент
    subprocess.Popen(["python", "graph.py", str(patient_id)], start_new_session=True)
    return "График!", 200


if __name__ == "__main__":
    app.run(debug=True)
