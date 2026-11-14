from email.message import EmailMessage

msg = EmailMessage()
msg["From"] = '"GitHub" <noreply@github.com>'
msg["Reply-To"] = "noreply@github.com"
msg["Return-Path"] = "<bounces@github.com>"
msg["To"] = "employee@example.com"
msg["Subject"] = "Your weekly digest"
msg["Message-ID"] = "<abc123@github.com>"
msg["Authentication-Results"] = (
    'mx.google.com; spf=pass smtp.mailfrom=github.com; '
    'dkim=pass header.d=github.com; '
    'dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com'
)
msg.set_content(
    "Hi,\n\nHere's your weekly digest of activity on your repositories.\n\n"
    "Visit https://github.com/notifications to see more.\n\nThanks,\nThe GitHub Team"
)

with open("clean_sample.eml", "wb") as f:
    f.write(msg.as_bytes())

print("Created clean_sample.eml")
