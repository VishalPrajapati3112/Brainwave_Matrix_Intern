import requests
import re
import socket
import base64
from urllib.parse import urlparse
import streamlit as st
import whois 
from datetime import datetime

# Defining Rule Based Checks for Offline View

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.hostname or parsed.netloc or parsed.path

def domain_exists(domain):
    if not domain:
        return False
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False

def is_localhost(url):
    parsed = urlparse(url)
    host = parsed.hostname
    return host in ["localhost" , "127.0.0.1" , "::1"] or url.startswith("file://")

def is_ip_in_url(url):
    return re.search(r"(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}", url) is not None

def is_exe_link(url):
    return url.lower().endswith(".exe")

def is_symbol(url):
    return "@" in url

def is_shortened(url):
    shorteners = ["bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"]
    domain = urlparse(url).netloc.lower()
    return any(short in domain for short in shorteners)

def format_url(url):
    if not url.startswith(('http://', 'https://', 'file://')):
        url = 'https://' + url
    return url

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme in ['http', 'https', 'file'] and (parsed.netloc or parsed.path):
            return True
    except:
        return False
    return False

def check(url):
    reasons = []
    parsed = urlparse(url)
    domain = extract_domain(url)

    if not domain:
        reasons.append("❌ Invalid URL or domain")
        return f"⚠️⚠️ Looking Suspicious in Check: {', '.join(reasons)}"
    
    if not domain_exists(domain):
        reasons.append("❌ Domain does NOT exist")
    if is_localhost(url):
        reasons.append("⚠️ It's a Localhost URL")
    if is_ip_in_url(url):
        reasons.append("⚠️ IP Address present in URL")
    if is_exe_link(url):
        reasons.append("💀 EXE file in URL, potentially harmful")
    if is_symbol(url):
        reasons.append("⚠️ '@' symbol present, possibly unsafe")
    if is_shortened(url):
        reasons.append("⚠️ Shortened URL detected, could be masking real destination")

    if reasons:
        return f"⚠️⚠️ Looking Suspicious in Check: {', '.join(reasons)}"
    else:
        return "✅✅ Looking Safe in Check\n✅ URL is safe ✅"

# VirusTotal API section
API_KEY = "1e7f889311b0143fa319b7e916099008941b7d8c34a2f9cdc83f9bf4acd829d6"
VT_BASE_URL = "https://www.virustotal.com/api/v3/urls"

def scan_url(url):
    headers = {"x-apikey": API_KEY}
    try:
        data = {"url": url}
        response = requests.post(VT_BASE_URL, headers=headers, data=data)
        if response.status_code != 200:
            return {"error": f":API STATUS ERROR: {response.status_code}"}

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        result_url = f"{VT_BASE_URL}/{url_id}"
        result = requests.get(result_url, headers=headers)

        if result.status_code != 200:
            return {"error": f"ERROR fetching results: {result.status_code}"}

        data = result.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "formatted": (
                f"VirusTotal Scan Result:\n"
                f"- Harmless: {stats.get('harmless', 0)}\n"
                f"- Suspicious: {stats.get('suspicious', 0)}\n"
                f"- Malicious: {stats.get('malicious', 0)}\n"
                f"- Undetected: {stats.get('undetected', 0)}"
            )
        }
    except Exception as e:
        return {"error": f"VirusTotal API Error: {str(e)}"}

def domain_info(url):
    try:
        domain = urlparse(url).netloc
        info = whois.whois(domain)
        return f"Created: {info.creation_date}\nExpires: {info.expiration_date}"
    except Exception as e:
        return f"WHOIS lookup Error: {str(e)}"

def save_log(url, result):
    try:
        with open(".phishing_log.txt", "a") as f:
            f.write(f"[{datetime.now()}] {url}\n{result}\n{'-'*50}\n")
    except:
        pass

# Streamlit GUI
st.set_page_config(page_title="Phishing Link Detector", page_icon="🛡️", layout="centered")

st.markdown("""
    <h1 style='text-align: center; color: #00FF00;'>🔐 Phishing Link Detector</h1>
    <p style='text-align: center; color: #aaa;'>Detect suspicious and phishing URLs using rules, WHOIS & VirusTotal API</p>
    <hr style='border-color: #333;'>
""", unsafe_allow_html=True)

url_input = st.text_input("🔗 Enter the URL to check:")

if url_input:
    url_input = url_input.strip()
    formatted_url = format_url(url_input)

    if not is_valid_url(formatted_url):
        st.error("❌ Invalid URL format. Please enter a valid URL (e.g., https://example.com)")
    else:
        col1, col2 = st.columns(2)

        if col1.button("Check Without Internet"):
            rule = check(url_input)
            whois_info = domain_info(url_input)
            result = f"{rule}\n{whois_info}"
            save_log(url_input, result)
            st.success(result)

        if col2.button("Check with API(⚠️Requires Internet Connection)"):
            rule = check(url_input)
            api_result = scan_url(url_input)
            whois_info = domain_info(url_input)

            full_result = f"{rule}\n{api_result.get('formatted', api_result.get('error'))}\n{whois_info}"
            save_log(url_input, full_result)
            
            api_message = api_result.get("formatted", api_result.get("error"))
            # Suspicious/Malicious Check
            if (
                "suspicious" in rule.lower()
                or api_result.get("malicious", 0) > 0
                or api_result.get("suspicious", 0) > 0
            ):
                st.warning(rule)
                st.warning(api_message)
            else:
                st.success(rule)
               
                st.info(api_message)
                

            # WHOIS
            if "error" in whois_info.lower() or "None" in whois_info:
                st.error(whois_info)
            else:
                st.info(whois_info)
                
st.markdown("---")
st.caption("🛈 **Note:** VirusTotal results depend on public reputation. Use manual check to detect **local/IP** based threats, obfuscated links, or suspicious patterns that VirusTotal might miss because there is high chance that they are **Fake Links** or You can **avoid** using that links.")


st.markdown("<hr><p style='text-align:center; color:gray;'>© 2025 Made by Vishal</p>", unsafe_allow_html=True)

