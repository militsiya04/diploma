import hashlib
import hmac
import secrets
from datetime import datetime, timedelta


def hash_otp(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return f"{salt}${hashed.hex()}"


def check_otp(password: str, hashed_password: str) -> bool:
    try:
        salt, hashed = hashed_password.split("$")
        new_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 100000
        ).hex()
        return hmac.compare_digest(new_hash, hashed)
    except Exception:
        return False


def store_otp(cursor, user_id: int, code: str, otp_type: str) -> None:
    expiry: datetime = datetime.now() + timedelta(minutes=5)
    hashed_code: str = hash_otp(code)

    cursor.execute(
        """
            DELETE FROM otp_tokens WHERE user_id = ? AND type = ?
        """,
        (user_id, otp_type),
    )

    cursor.execute(
        """
        INSERT INTO otp_tokens (user_id, code, type, expiry, used)
        VALUES (?, ?, ?, ?, ?)
    """,
        (user_id, hashed_code, otp_type, expiry.strftime("%Y-%m-%d %H:%M:%S"), False),
    )


def validate_otp(cursor, user_id: int, code: str, otp_type: str) -> bool:
    cursor.execute(
        """
        SELECT code, expiry, used FROM otp_tokens 
        WHERE user_id = ? AND type = ?
    """,
        (user_id, otp_type),
    )

    row = cursor.fetchone()
    if not row:
        return False

    stored_hash: str = row[0]
    expiry_datetime: datetime = row[1]
    used: bool = row[2]

    if used or datetime.now() > expiry_datetime:
        return False

    if check_otp(code, stored_hash):
        cursor.execute(
            """
            UPDATE otp_tokens SET used = 1
            WHERE user_id = ? AND type = ?
        """,
            (user_id, otp_type),
        )
        return True

    return False
