import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg2://dietapp:devpassword_local_only@localhost:5432/dietapp"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Invio email — interfaccia collegabile.
# In sviluppo/test: EmailSender "log" che stampa il link invece di inviarlo.
# In produzione: impostare EMAIL_PROVIDER=smtp (o sendgrid) e le relative
# variabili d'ambiente (host, porta, credenziali) — vedi README.
# ---------------------------------------------------------------------------
class LogEmailSender:
    """Non invia nulla: stampa il contenuto. Usato in sviluppo/test."""
    def send_password_reset(self, to_email: str, reset_link: str):
        print(f"[EMAIL SIMULATA] A: {to_email} — Link di reset: {reset_link}")


class SMTPEmailSender:
    """Invio reale via SMTP. Richiede SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM."""
    def __init__(self):
        import smtplib
        self.smtplib = smtplib
        self.host = os.environ["SMTP_HOST"]
        self.port = int(os.environ.get("SMTP_PORT", 587))
        self.user = os.environ["SMTP_USER"]
        self.password = os.environ["SMTP_PASS"]
        self.from_addr = os.environ.get("SMTP_FROM", self.user)

    def send_password_reset(self, to_email: str, reset_link: str):
        from email.mime.text import MIMEText
        msg = MIMEText(
            f"Hai chiesto di reimpostare la password di Monitora la tua dieta.\n\n"
            f"Apri questo link per scegliere una nuova password (valido 1 ora):\n{reset_link}\n\n"
            f"Se non hai richiesto tu il reset, ignora questa email."
        )
        msg["Subject"] = "Reimposta la tua password"
        msg["From"] = self.from_addr
        msg["To"] = to_email
        with self.smtplib.SMTP(self.host, self.port) as server:
            server.starttls()
            server.login(self.user, self.password)
            server.sendmail(self.from_addr, [to_email], msg.as_string())


def get_email_sender():
    provider = os.environ.get("EMAIL_PROVIDER", "log")
    if provider == "smtp":
        return SMTPEmailSender()
    return LogEmailSender()

# by Lorè
