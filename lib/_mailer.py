# api/_mailer.py
import os as _os, sys as _sys
# Add lib/ to path — works both locally and in Vercel (/var/task/lib)
for _candidate in [
    _os.path.dirname(_os.path.abspath(__file__)),          # local: lib/ itself
    '/var/task/lib',                                        # Vercel production
    _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', 'lib'),  # fallback
]:
    if _os.path.isdir(_candidate) and _candidate not in _sys.path:
        _sys.path.insert(0, _candidate)

"""SMTP email dispatcher for OTP delivery."""
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTP_HOST       = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT       = int(os.environ.get("SMTP_PORT", 587))
SMTP_USE_TLS    = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"
SMTP_USER       = os.environ.get("SMTP_USERNAME", "")
SMTP_PASS       = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM_NAME  = os.environ.get("SMTP_FROM_NAME", "Serenity Psychiatric Care")
SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL", "noreply@example.com")
OTP_EXPIRE_MINS = int(os.environ.get("OTP_EXPIRE_MINUTES", 5))


def send_otp_email(recipient: str, otp: str, full_name: str = "") -> None:
    greeting = f"Dear {full_name}," if full_name else "Hello,"
    html = f"""
    <html><body style="font-family:Inter,Arial,sans-serif;background:#f8fafc;margin:0;padding:0;">
      <div style="max-width:480px;margin:40px auto;background:#fff;border-radius:16px;
                  border:1px solid #e2e8f0;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.06);">
        <div style="background:#0f766e;padding:32px;text-align:center;">
          <h1 style="color:#fff;margin:0;font-size:22px;">🌿 Serenity Psychiatric Care</h1>
          <p style="color:#99f6e4;margin:8px 0 0;font-size:13px;">Secure Clinical Portal</p>
        </div>
        <div style="padding:32px;">
          <p style="color:#334155;">{greeting}</p>
          <p style="color:#475569;font-size:14px;">Your one-time verification code is:</p>
          <div style="background:#f0fdf4;border:2px solid #86efac;border-radius:12px;
                      padding:20px;text-align:center;margin:20px 0;">
            <span style="font-size:40px;font-weight:700;letter-spacing:12px;color:#15803d;
                         font-family:'Courier New',monospace;">{otp}</span>
          </div>
          <p style="color:#94a3b8;font-size:12px;">
            Expires in <strong>{OTP_EXPIRE_MINS} minutes</strong>.<br>
            If you did not request this, contact your administrator immediately.
          </p>
        </div>
        <div style="background:#f8fafc;padding:16px 32px;text-align:center;border-top:1px solid #e2e8f0;">
          <p style="color:#cbd5e1;font-size:11px;margin:0;">HIPAA-compliant automated message. Do not reply.</p>
        </div>
      </div>
    </body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your Serenity Portal Verification Code"
    msg["From"]    = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    msg["To"]      = recipient
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as srv:
        if SMTP_USE_TLS:
            srv.starttls()
        if SMTP_USER and SMTP_PASS:
            srv.login(SMTP_USER, SMTP_PASS)
        srv.sendmail(SMTP_FROM_EMAIL, [recipient], msg.as_string())
