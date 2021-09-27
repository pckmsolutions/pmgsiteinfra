from flask import current_app
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from logging import getLogger

logger = getLogger(__name__)

class SendEmail:
    def __init__(self, *,
            dummy_mode=False,
            sender_addr=None,
            host=None,
            port=None,
            username=None,
            password=None):
        self.dummy_mode = dummy_mode
        self.sender_addr = sender_addr
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    def __call__(self, *, addr, subject_template, body_template, **args):
        render_args = args

        subject = current_app.jinja_env.get_template(
                f'{subject_template}').render(**render_args)
        text = current_app.jinja_env.get_template(
                f'{body_template}.text').render(**render_args)
        if self.dummy_mode:
            logger.info(f'Skipping SMTP send. Would be sending to {addr}: {text}')
            return
        html = current_app.jinja_env.get_template(
                f'{body_template}.html').render(**render_args)

        msg = MIMEMultipart("alternative")

        sender = self.sender_addr

        msg.add_header('From', sender)
        msg.add_header('To', addr)
        msg.add_header('Subject', subject)

        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP_SSL(host=self.host,
                port=self.port,
                context=ssl.create_default_context()) as smtp_server:
            smtp_server.login(self.username, self.password)
            smtp_server.sendmail(sender, addr, msg.as_string())





