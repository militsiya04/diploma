from datetime import datetime, timedelta

from app.utils import check_password, hash_password


def store_otp(cursor, user_id: int, code: str, otp_type: str) -> None:
    expiry: datetime = datetime.now() + timedelta(minutes=5)
    hashed_code: str = hash_password(code)

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

    if check_password(code, stored_hash):
        cursor.execute(
            """
            UPDATE otp_tokens SET used = 1
            WHERE user_id = ? AND type = ?
        """,
            (user_id, otp_type),
        )
        return True

    return False
