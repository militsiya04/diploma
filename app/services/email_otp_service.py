import random

from flask import Flask, session
from flask_mail import Mail, Message

mail: Mail = Mail()


def configure_mail(app: Flask) -> None:
    app.config["MAIL_SERVER"] = "smtp.gmail.com"
    app.config["MAIL_PORT"] = 587
    app.config["MAIL_USE_TLS"] = True
    app.config["MAIL_USERNAME"] = "JetStreamPo@gmail.com"
    app.config["MAIL_PASSWORD"] = "cwyyszlwtabkcdpd"
    mail.init_app(app)


def send_otp_email(email: str, otp: str) -> None:
    msg: Message = Message(
        subject="Your Authentication Code",
        sender="default@example.com",
        recipients=[email],
    )
    msg.body = f"Your authentication code is {otp}"
    mail.send(msg)
