import re
import ipaddress
import streamlit as st
from urllib.parse import urlparse

st.set_page_config(
    page_title="Phishing Website Detector",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 Phishing Website Detector")

st.write(
    "Check website links for common signs of phishing "
    "and learn how to browse more safely."
)

st.warning(
    "This tool provides a preliminary risk assessment. "
    "It cannot guarantee that a website is safe or malicious."
)


def check_url(url):
    url = url.strip()

    if not url:
        return "Invalid", ["Please enter a website URL."]

    if any(char.isspace() for char in url):
        return "Invalid", ["The URL contains spaces."]

    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        host = parsed.hostname

        if not host:
            return "Invalid", ["The URL has no valid hostname."]

    except ValueError:
        return "Invalid", ["The URL format is invalid."]

    warnings = []

    if parsed.scheme != "https":
        warnings.append("The URL does not use HTTPS.")

    if "@" in parsed.netloc:
        warnings.append("The URL contains an @ symbol.")

    if len(url) > 100:
        warnings.append("The URL is unusually long.")

    if host.count(".") > 4:
        warnings.append("The hostname has many subdomains.")

    if "-" in host:
        warnings.append("The hostname contains hyphens.")

    if any(char.isdigit() for char in host):
        try:
            ipaddress.ip_address(host)
            warnings.append(
                "The website uses an IP address instead of a domain."
            )
        except ValueError:
            pass

    suspicious_words = [
        "login", "verify", "secure", "account",
        "password", "update", "wallet"
    ]

    if any(word in url.lower() for word in suspicious_words):
        warnings.append(
            "The URL contains words sometimes used in phishing links."
        )

    if warnings:
        return "Caution", warnings

    return "No common warning signs detected", []


url = st.text_input(
    "Enter a website URL",
    placeholder="https://example.com"
)

if st.button("Check Website", type="primary"):
    status, warnings = check_url(url)

    if status == "Invalid":
        st.error("Invalid URL")
        for warning in warnings:
            st.write("- " + warning)

    elif warnings:
        st.warning("⚠️ Caution: Suspicious indicators found")

        for warning in warnings:
            st.write("- " + warning)

        st.info(
            "Avoid entering passwords or banking details "
            "until you independently verify the website."
        )

    else:
        st.success(
            "No common warning signs were detected."
        )

        st.info(
            "This does not prove the website is safe. "
            "Remain cautious and verify unfamiliar websites."
        )

st.divider()

st.subheader("🛡️ Online Safety Tips")

st.markdown("""
- Do not share your password through suspicious links.
- Check website addresses carefully.
- Be cautious of urgent messages asking you to act.
- Never enter banking details on an unverified website.
- Enable two-factor authentication where available.
""")

st.caption(
    "Cybersecurity Capstone Project | 3MTT NextGen"
)
