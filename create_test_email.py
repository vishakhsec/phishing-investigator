from email.message import EmailMessage

msg = EmailMessage()
msg["From"] = '"Microsoft Security" <support@micros0ft-security.com>'
msg["Reply-To"] = "attacker@totally-different-domain.ru"
msg["Return-Path"] = "<bounce@sketchy-mailer.net>"
msg["To"] = "employee@example.com"
msg["Subject"] = "Urgent - Your Microsoft Account Will Be Blocked"
msg["Message-ID"] = "<12345@micros0ft-security.com>"
msg["Authentication-Results"] = (
    'mx.google.com; spf=fail (google.com: domain of bounce@sketchy-mailer.net '
    'does not designate permitted sender hosts) smtp.mailfrom=sketchy-mailer.net; '
    'dkim=none (message not signed); dmarc=fail (p=REJECT sp=REJECT dis=NONE) '
    'header.from=micros0ft-security.com'
)
msg.set_content(
    "Dear User,\n\nWe detected unusual activity on your account. "
    "Click the link below to verify your account immediately or it will be blocked within 24 hours.\n\n"
    "http://micros0ft-security.com/login\n\nMicrosoft Security Team"
)

# Fake malicious attachment: looks like a PDF, is actually an .exe
fake_exe_content = b"MZ" + b"\x00" * 100  # MZ = real Windows .exe file signature
msg.add_attachment(
    fake_exe_content,
    maintype="application",
    subtype="octet-stream",
    filename="Invoice_2026.pdf.exe"
)

with open("phishing_sample.eml", "wb") as f:
    f.write(msg.as_bytes())

print("Created phishing_sample.eml with attachment")
