import hashlib
import hmac
import os
import secrets
import time
from functools import wraps

from flask import flash, redirect, session, url_for

SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "super-secret")


def generate_session_token(user_id, role):
    message = f"{user_id}:{role}"
    return hmac.new(SECRET_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()


def is_fully_authenticated():
    user_id = session.get("user_id")
    role = session.get("role")
    token = session.get("session_token")

    if not all([user_id, role, token]):
        return False

    expected = generate_session_token(user_id, role)
    return hmac.compare_digest(expected, token)


def allowed_file(filename: str):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"xlsx"}


def login_required_with_timeout(timeout_minutes=15):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not is_fully_authenticated():
                flash("Будь ласка, увійдіть в систему.", "error")
                return redirect(url_for("login"))

            last_active = session.get("last_active")
            now = time.time()

            if last_active and (now - last_active > timeout_minutes * 60):
                session.clear()
                flash("Сесія завершена. Увійдіть повторно.", "warning")
                return redirect(url_for("logout"))

            session["last_active"] = now
            return f(*args, **kwargs)

        return wrapped

    return decorator


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return f"{salt}${hashed.hex()}"


def check_password(password: str, hashed_password: str) -> bool:
    try:
        salt, hashed = hashed_password.split("$")
        new_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 100000
        ).hex()
        return hmac.compare_digest(new_hash, hashed)
    except Exception:
        return False


def roles_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not is_fully_authenticated():
                flash("Будь ласка, увійдіть в систему.", "error")
                return redirect(url_for("login"))

            role = session.get("role")
            if role not in allowed_roles:
                flash("Недостатньо прав для доступу.", "warning")
                return redirect(url_for("unauthorized"))

            return f(*args, **kwargs)

        return wrapped

    return decorator
