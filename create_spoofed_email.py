from email.message import EmailMessage

msg = EmailMessage()
msg["From"] = '"PayPal Support" <service@paypal.com>'
msg["Reply-To"] = "refunds@totally-fake-paypal.ru"
msg["Return-Path"] = "<bounce@paypal.com>"
msg["To"] = "employee@example.com"
msg["Subject"] = "Your refund is ready"
msg["Message-ID"] = "<xyz789@paypal.com>"
msg["Authentication-Results"] = (
    'mx.google.com; spf=pass smtp.mailfrom=paypal.com; '
    'dkim=pass header.d=paypal.com; '
    'dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com'
)
msg.set_content(
    "Hi,\n\nYour refund of $49.99 is ready. Reply to this email to confirm your bank details.\n\nThanks,\nPayPal Support"
)

with open("spoofed_sample.eml", "wb") as f:
    f.write(msg.as_bytes())

print("Created spoofed_sample.eml")
