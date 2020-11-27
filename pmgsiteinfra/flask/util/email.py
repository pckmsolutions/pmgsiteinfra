from flask import current_app
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from logging import getLogger

logger = getLogger(__name__)

def send_email(addr, subject_template, body_template, **args):
    render_args = args

    subject = current_app.jinja_env.get_template(
            f'{subject_template}').render(**render_args)
    text = current_app.jinja_env.get_template(
            f'{body_template}.text').render(**render_args)
    if current_app.config['SMTP_SKIP']:
        logger.info(f'Skipping SMTP send. Would be sending to {addr}: {text}')
        return
    html = current_app.jinja_env.get_template(
            f'{body_template}.html').render(**render_args)

    msg = MIMEMultipart("alternative")

    sender = current_app.config['SMTP_SENDER_ADDR']

    msg.add_header('From', f'{sender} <{sender}>')
    msg.add_header('To', f'{addr} <{addr}>')
    msg.add_header('Subject', subject)

    msg.attach(MIMEText(text, 'plain'))
    msg.attach(MIMEText(html, 'html'))

    with smtplib.SMTP_SSL(host=current_app.config['SMTP_HOST'],
            port=current_app.config['SMTP_PORT'],
            context=ssl.create_default_context()) as smtp_server:
        smtp_server.login(current_app.config['SMTP_USERNAME'],
                current_app.config['SMTP_PASSWORD'])
        smtp_server.sendmail(sender, addr, msg.as_string())





