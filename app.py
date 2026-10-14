
import re
import ipaddress
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st

st.set_page_config(
    page_title="PhishShield AI",
    page_icon="🛡️",
    layout="centered"
)

# ---------- DETECTION ENGINE ----------

URGENT_WORDS = [
    "urgent", "immediately", "account blocked",
    "account suspended", "verify now", "act now",
    "limited time", "expires today"
]

SENSITIVE_WORDS = [
    "password", "otp", "one time password",
    "bank account", "credit card", "pin number",
    "login details", "confirm your identity"
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "cutt.ly", "shorturl.at"
}

URL_PATTERN = r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""


def extract_urls(text):
    return re.findall(URL_PATTERN, text)


def analyze_url(raw_url):
    findings = []
    score = 0

    # Normalize URL for parsing; never open or visit it.
    url = raw_url.strip().rstrip(".,!?;:)")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if not host:
            return 0, ["Could not identify a valid hostname."]

        try:
            ipaddress.ip_address(host)
            score += 30
            findings.append("URL uses an IP address instead of a domain.")
        except ValueError:
            pass

        if parsed.scheme == "http":
            score += 10
            findings.append("URL uses unencrypted HTTP.")

        if "@" in parsed.netloc:
            score += 25
            findings.append("URL contains an @ sign in its authority section.")

        if host.startswith("xn--") or ".xn--" in host:
            score += 20
            findings.append("Hostname contains punycode.")

        if host in SHORTENERS:
            score += 15
            findings.append("URL uses a known link-shortening service.")

        if len(host) > 45:
            score += 10
            findings.append("Hostname is unusually long.")

        if len(host.split(".")) >= 5:
            score += 10
            findings.append("Hostname has many subdomain levels.")

        if not findings:
            findings.append(
                "No listed URL warning patterns were detected."
            )

    except Exception:
        findings.append("Unable to parse this URL.")

    return min(score, 100), findings


def analyze_message(message):
    score = 0
    findings = []
    text = message.lower()

    for word in URGENT_WORDS:
        if word in text:
            score += 15
            findings.append(
                f"Urgency indicator: '{word}'"
            )

    for word in SENSITIVE_WORDS:
        if word in text:
            score += 20
            findings.append(
                f"Sensitive-information indicator: '{word}'"
            )

    urls = extract_urls(message)

    for url in urls:
        url_score, url_findings = analyze_url(url)
        score += url_score

        for finding in url_findings:
            if finding not in findings:
                findings.append(finding)

    if not findings:
        findings.append(
            "No listed warning patterns were detected."
        )

    score = min(score, 100)

    if score >= 50:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "findings": findings,
        "urls": urls
    }


# ---------- USER INTERFACE ----------

st.title("🛡️ PhishShield AI")
st.caption("Phishing & Digital Scam Risk Analyzer")

st.info(
    "Prototype: uses security rules, not a trained AI model. "
    "Results are risk indicators, not proof."
)

if "history" not in st.session_state:
    st.session_state.history = []

st.subheader("🔎 Scan a message or URL")

sample = st.selectbox(
    "Try a sample",
    [
        "Custom input",
        "Suspicious bank alert",
        "Ordinary college message",
        "Suspicious URL example"
    ]
)

samples = {
    "Suspicious bank alert":
        "URGENT! Your bank account is suspended. "
        "Verify your password immediately at "
        "http://192.0.2.1/login",

    "Ordinary college message":
        "Your college assignment submission has been received.",

    "Suspicious URL example":
        "Check this link: http://192.0.2.1/verify"
}

default_text = samples.get(sample, "")

message = st.text_area(
    "Paste message or URL",
    value=default_text,
    height=150,
    placeholder="Paste a suspicious SMS, email, or URL here..."
)

if st.button("🔍 Scan Message", type="primary",
             use_container_width=True):

    if not message.strip():
        st.warning("Please enter a message or URL.")
    else:
        result = analyze_message(message)

        st.session_state.history.insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": result["level"],
            "score": result["score"],
            "message": message[:100]
        })

        st.subheader("📊 Scan Results")

        col1, col2 = st.columns(2)
        col1.metric("Risk Score", f'{result["score"]}/100')
        col2.metric("Risk Level", result["level"])

        if result["level"] == "HIGH":
            st.error("High risk — do not click or share information.")
        elif result["level"] == "MEDIUM":
            st.warning("Caution — verify the sender independently.")
        else:
            st.success(
                "Low detected risk — this does NOT prove the "
                "message or link is safe."
            )

        st.write("**Why was it flagged?**")
        for finding in result["findings"]:
            st.write(f"• {finding}")

        if result["urls"]:
            st.write("**URLs found in the message:**")
            for url in result["urls"]:
                st.code(url)

        st.write("**Recommended actions**")
        st.write(
            "- Do not share passwords, PINs, or OTPs.\n"
            "- Open official websites using a known address "
            "or the official app.\n"
            "- Verify unexpected requests using a trusted "
            "contact method."
        )

st.divider()
st.subheader("🕘 Recent Scan History")

if st.session_state.history:
    st.dataframe(
        st.session_state.history,
        use_container_width=True,
        hide_index=True
    )
    if st.button("Clear History"):
        st.session_state.history = []
        st.rerun()
else:
    st.caption("Your scan history will appear here.")

st.divider()
st.caption(
    "Educational prototype • URLs are analyzed locally "
    "without visiting them • Not a guarantee of safety"
)
