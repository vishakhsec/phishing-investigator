from flask import Flask, request, Response
from markupsafe import escape
import email
from email import policy
import re
import hashlib
import base64
import os
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

app = Flask(__name__)

latest_report = {"text": None}

UPLOAD_FORM = """
<h2>Phishing Investigator</h2>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="eml_file">
    <input type="submit" value="Upload Email">
</form>
"""

def parse_auth_results(auth_header):
    if not auth_header:
        return {"spf": "Not available", "dkim": "Not available", "dmarc": "Not available"}
    results = {}
    for check in ["spf", "dkim", "dmarc"]:
        match = re.search(rf"{check}=(\w+)", auth_header, re.IGNORECASE)
        results[check] = match.group(1) if match else "Not available"
    return results

def extract_urls(text):
    if not text:
        return []
    url_pattern = r'https?://[^\s<>"\']+'
    return re.findall(url_pattern, text)

def get_domain(email_address):
    if not email_address:
        return None
    match = re.search(r'@([\w\.-]+)', email_address)
    return match.group(1).lower() if match else None

def check_url(url):
    flags = []
    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
        flags.append("Uses raw IP address instead of domain")
    if url.startswith("http://"):
        flags.append("Not using HTTPS (unencrypted)")
    typosquat_patterns = ["micr0soft", "micros0ft", "g00gle", "paypa1", "amaz0n"]
    for pattern in typosquat_patterns:
        if pattern in url.lower():
            flags.append(f"Possible typosquatting: contains '{pattern}'")
    if not flags:
        flags.append("No obvious red flags detected")
    return flags

def check_url_virustotal(url):
    if not VT_API_KEY:
        return "VirusTotal API key not configured"
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return f"{malicious} malicious, {suspicious} suspicious (out of {sum(stats.values())} vendors)"
        elif response.status_code == 404:
            return "Not previously seen by VirusTotal"
        else:
            return f"VirusTotal error: {response.status_code}"
    except Exception as e:
        return f"VirusTotal check failed: {str(e)}"

def check_hash_virustotal(sha256_hash):
    if not VT_API_KEY:
        return "VirusTotal API key not configured"
    try:
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256_hash}",
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return f"{malicious} malicious, {suspicious} suspicious (out of {sum(stats.values())} vendors)"
        elif response.status_code == 404:
            return "Not previously seen by VirusTotal"
        else:
            return f"VirusTotal error: {response.status_code}"
    except Exception as e:
        return f"VirusTotal check failed: {str(e)}"

def analyze_attachments(msg):
    results = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        content = part.get_payload(decode=True)
        sha256_hash = hashlib.sha256(content).hexdigest()

        if content.startswith(b"MZ"):
            real_type = "Windows Executable (.exe) - DANGEROUS if disguised"
        elif content.startswith(b"%PDF"):
            real_type = "PDF document"
        else:
            real_type = "Unknown type"

        vt_result = check_hash_virustotal(sha256_hash)

        results.append({
            "filename": filename,
            "real_type": real_type,
            "sha256": sha256_hash,
            "size": len(content),
            "vt_result": vt_result
        })
    return results

def calculate_risk_score(auth_results, url_results, attachments, sender, reply_to, return_path):
    score = 0
    reasons = []

    if auth_results["spf"] == "fail":
        score += 20
        reasons.append("SPF authentication failed (+20)")
    if auth_results["dkim"] in ("none", "fail"):
        score += 15
        reasons.append("DKIM missing or failed (+15)")
    if auth_results["dmarc"] == "fail":
        score += 20
        reasons.append("DMARC authentication failed (+20)")

    from_domain = get_domain(sender)
    reply_to_domain = get_domain(reply_to)
    return_path_domain = get_domain(return_path)

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        score += 35
        reasons.append(f"Reply-To domain ({reply_to_domain}) does not match From domain ({from_domain}) (+35)")

    if return_path_domain and from_domain and return_path_domain != from_domain:
        score += 20
        reasons.append(f"Return-Path domain ({return_path_domain}) does not match From domain ({from_domain}) (+20)")

    for url, flags in url_results.items():
        if "Possible typosquatting" in " ".join(flags):
            score += 25
            reasons.append(f"Typosquatting detected in URL: {url} (+25)")
        if "Not using HTTPS" in flags:
            score += 10
            reasons.append(f"Insecure HTTP link: {url} (+10)")
        if "Uses raw IP address" in " ".join(flags):
            score += 15
            reasons.append(f"Raw IP address used in URL: {url} (+15)")

    for att in attachments:
        if "DANGEROUS" in att["real_type"]:
            score += 30
            reasons.append(f"Disguised executable attachment: {att['filename']} (+30)")
        if "malicious" in att["vt_result"] and not att["vt_result"].startswith("0 malicious"):
            score += 40
            reasons.append(f"VirusTotal flagged attachment as malicious (+40)")

    if score >= 50:
        level = "HIGH RISK"
    elif score >= 20:
        level = "MEDIUM RISK"
    else:
        level = "LOW RISK"

    return score, level, reasons

def map_mitre_attack(url_results, attachments, risk_reasons):
    techniques = []

    has_suspicious_url = any(
        "typosquatting" in " ".join(flags).lower() or "ip address" in " ".join(flags).lower()
        for flags in url_results.values()
    )
    if has_suspicious_url:
        techniques.append("T1566.002 - Phishing: Spearphishing Link")

    if any("DANGEROUS" in att["real_type"] for att in attachments):
        techniques.append("T1566.001 - Phishing: Spearphishing Attachment")

    if any("Reply-To domain" in r for r in risk_reasons):
        techniques.append("T1656 - Impersonation")

    if not techniques:
        techniques.append("No specific MITRE ATT&CK techniques identified")

    return techniques

def build_text_report(subject, sender, reply_to, return_path, message_id,
                       auth_results, url_results, attachments,
                       risk_score, risk_level, risk_reasons, mitre_techniques):
    lines = []
    lines.append("=" * 60)
    lines.append("PHISHING EMAIL INVESTIGATION REPORT")
    lines.append("=" * 60)
    lines.append(f"Investigation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("1. EMAIL DETAILS")
    lines.append(f"   Subject:     {subject}")
    lines.append(f"   From:        {sender}")
    lines.append(f"   Reply-To:    {reply_to}")
    lines.append(f"   Return-Path: {return_path}")
    lines.append(f"   Message-ID:  {message_id}")
    lines.append("")
    lines.append("2. AUTHENTICATION RESULTS")
    lines.append(f"   SPF:   {auth_results['spf']}")
    lines.append(f"   DKIM:  {auth_results['dkim']}")
    lines.append(f"   DMARC: {auth_results['dmarc']}")
    lines.append("")
    lines.append("3. URL ANALYSIS")
    for url, flags in url_results.items():
        lines.append(f"   URL: {url}")
        for flag in flags:
            lines.append(f"      - {flag}")
    lines.append("")
    lines.append("4. ATTACHMENT ANALYSIS")
    if attachments:
        for att in attachments:
            lines.append(f"   Filename: {att['filename']}")
            lines.append(f"   Real type: {att['real_type']}")
            lines.append(f"   SHA-256: {att['sha256']}")
            lines.append(f"   VirusTotal: {att['vt_result']}")
    else:
        lines.append("   No attachments found")
    lines.append("")
    lines.append("5. RISK ASSESSMENT")
    lines.append(f"   Risk Level: {risk_level}")
    lines.append(f"   Risk Score: {risk_score}")
    for reason in risk_reasons:
        lines.append(f"      - {reason}")
    lines.append("")
    lines.append("5b. MITRE ATT&CK MAPPING")
    for tech in mitre_techniques:
        lines.append(f"   - {tech}")
    lines.append("")
    lines.append("6. ANALYST VERDICT")
    if risk_level == "HIGH RISK":
        lines.append("   Suspicious - Further Investigation Required / Likely Phishing")
    elif risk_level == "MEDIUM RISK":
        lines.append("   Suspicious - Further Investigation Required")
    else:
        lines.append("   Benign - No major indicators found")
    lines.append("")
    lines.append("7. RECOMMENDATIONS")
    lines.append("   - Block sender domain and reported URLs at the email gateway")
    lines.append("   - Quarantine or delete the email from all mailboxes")
    lines.append("   - Check whether other employees received the same email")
    lines.append("   - Do not open or execute any attachments")
    lines.append("   - Escalate to the incident response team if user interacted with the email")
    lines.append("=" * 60)
    return "\n".join(lines)

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        file = request.files["eml_file"]
        msg = email.message_from_bytes(file.read(), policy=policy.default)
        subject = msg["subject"]
        sender = msg["from"]
        reply_to = msg["reply-to"]
        return_path = msg["return-path"]
        message_id = msg["message-id"]
        auth_results_raw = msg["Authentication-Results"]
        auth_results = parse_auth_results(auth_results_raw)
        body = msg.get_body(preferencelist=('plain')).get_content()
        urls = extract_urls(body)
        url_results = {url: check_url(url) for url in urls}
        attachments = analyze_attachments(msg)
        risk_score, risk_level, risk_reasons = calculate_risk_score(auth_results, url_results, attachments, sender, reply_to, return_path)
        mitre_techniques = map_mitre_attack(url_results, attachments, risk_reasons)

        latest_report["text"] = build_text_report(
            subject, sender, reply_to, return_path, message_id,
            auth_results, url_results, attachments,
            risk_score, risk_level, risk_reasons, mitre_techniques
        )

        url_html = ""
        reasons_html = "".join(f"<li>{escape(r)}</li>" for r in risk_reasons)
        mitre_html = "".join(f"<li>{escape(t)}</li>" for t in mitre_techniques)
        for url, flags in url_results.items():
            flag_list = "".join(f"<li>{escape(flag)}</li>" for flag in flags)
            vt_result = check_url_virustotal(url)
            url_html += f"<p><b>{escape(url)}</b><ul>{flag_list}</ul><b>VirusTotal:</b> {escape(vt_result)}</p>"

        attachment_html = ""
        for att in attachments:
            attachment_html += f"""
            <p><b>Filename:</b> {escape(att['filename'])}<br>
            <b>Real file type:</b> {escape(att['real_type'])}<br>
            <b>Size:</b> {att['size']} bytes<br>
            <b>SHA-256:</b> {escape(att['sha256'])}<br>
            <b>VirusTotal:</b> {escape(att['vt_result'])}</p>
            """

        return f"""
        <h2>Risk Level: {risk_level} (Score: {risk_score})</h2>
        <h3>Risk Factors:</h3>
        <ul>{reasons_html}</ul>
        <h3>MITRE ATT&CK Mapping:</h3>
        <ul>{mitre_html}</ul>
        <p><a href="/download_report"><button>Download Investigation Report</button></a></p>
        <hr>
        <h3>Subject:</h3> {escape(subject)}<br>
        <h3>From:</h3> {escape(sender)}<br>
        <h3>Reply-To:</h3> {escape(reply_to)}<br>
        <h3>Return-Path:</h3> {escape(return_path)}<br>
        <h3>Message-ID:</h3> {escape(message_id)}<br>
        <h3>SPF:</h3> {escape(auth_results['spf'])}<br>
        <h3>DKIM:</h3> {escape(auth_results['dkim'])}<br>
        <h3>DMARC:</h3> {escape(auth_results['dmarc'])}<br>
        <h3>URL Analysis:</h3>
        {url_html}
        <h3>Attachment Analysis:</h3>
        {attachment_html if attachment_html else "No attachments found"}
        """
    return UPLOAD_FORM

@app.route("/download_report")
def download_report():
    if not latest_report["text"]:
        return "No report available yet. Please analyze an email first."
    return Response(
        latest_report["text"],
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment;filename=investigation_report.txt"}
    )

if __name__ == "__main__":
    app.run(debug=True)

