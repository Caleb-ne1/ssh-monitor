import yaml
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config.setup_config import load_config
# load config
config = load_config()
    
email_cfg = config["email"]

def send_email(subject: str, message: str, is_html: bool = False):
    try:
        msg = MIMEMultipart()
        msg['From'] = email_cfg["sender_email"]
        msg['To'] = email_cfg["recipient_email"]
        msg['Subject'] = subject

        content_type = "html" if is_html else "plain"
        msg.attach(MIMEText(message, content_type))

        server = smtplib.SMTP(email_cfg["smtp_server"], email_cfg["smtp_port"])
        server.starttls()
        server.login(email_cfg["sender_email"], email_cfg["app_password"])
        server.send_message(msg)
        server.quit()

        print(f"✅ Email sent: {subject}")

    except Exception as e:
        print(f"⚠️ Failed to send email: {e}")