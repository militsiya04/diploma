from datetime import datetime, timedelta


def store_otp(cursor, user_id: int, code: str, otp_type: str) -> None:
    expiry: datetime = datetime.now() + timedelta(minutes=5)
    cursor.execute(
        """
        INSERT INTO otp_tokens (user_id, code, type, expiry, used)
        VALUES (?, ?, ?, ?, ?)
    """,
        (user_id, code, otp_type, expiry.strftime("%Y-%m-%d %H:%M:%S"), False),
    )


def validate_otp(cursor, user_id: int, code: str, otp_type: str) -> bool:
    cursor.execute(
        """
        SELECT expiry, used FROM otp_tokens 
        WHERE user_id = ? AND code = ? AND type = ?
        ORDER BY expiry DESC
    """,
        (user_id, code, otp_type),
    )

    row = cursor.fetchone()
    if not row:
        return False

    expiry_str: datetime = row[0]
    used: bool = row[1]

    if used:
        return False
    if datetime.now() > expiry_str:
        return False

    cursor.execute(
        """
        UPDATE otp_tokens SET used = 1
        WHERE user_id = ? AND code = ? AND type = ?
    """,
        (user_id, code, otp_type),
    )
    return True
