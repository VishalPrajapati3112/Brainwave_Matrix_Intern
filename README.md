# Brainwave_Matrix_Intern

# 🛡️ Phishing Link Scanner

**Phishing Link Scanner** is a lightweight and effective web application that detects potentially malicious or suspicious URLs using rule-based logic, WHOIS data, and VirusTotal API analysis.

> 🔗 Built with **Python**, **Streamlit**, and integrated with **VirusTotal** API to enhance phishing threat detection.

## 🚀 Features

- ✅ Detects suspicious patterns: IP-based URLs, shortened links, `@` symbols, `.exe` files, etc.
- 🌐 Performs **WHOIS lookup** to show domain creation/expiry dates.
- 🦠 Scans links with **VirusTotal API** for reputation-based results.
- 💾 Saves scan history in `.phishing_log.txt`.
- 📸 Includes screenshots of the working output in `output/results/`.
- ☁️ Deployable on **Streamlit Cloud** with shareable public link.

---

## 📁 Project Structure

├── phishing-detector.py                     # Main Streamlit app
├── .phishing_log.txt                        # Auto-saved log of scanned URLs
├── PHISHING LINK SCANNER report.pdf         # Project report (or .docx)
├── requirements.txt                         # Dependencies for the project
│
├── output/results
│ ├── 1.png
│ └── 2.png
   and so on ...


---

## ⚙️ Installation

### 🧩 Prerequisites

- Python 3.7+
- Internet connection (for VirusTotal & WHOIS lookups)

### 🛠️ Steps

1. Clone this repository
2. Install dependencies
3. Run the app
streamlit run phishing-detector.py

Or Simply Open this Link "https://phishing-url-scanner.streamlit.app/" 


## 📊 Example Outputs

Screenshots are available in the output/results/ folder showing:
✅ Safe link scan result
⚠️ Suspicious traits (localhost, IPs, shorteners)
🧾 WHOIS output
🦠 VirusTotal scan statistics


## 📚 Technologies Used

Python 3
Streamlit
VirusTotal Public API
WHOIS

## You can use  " https://phishing-url-scanner.streamlit.app/ " this link to check my website.

## ✍️ Author
Made with ❤️ by Vishal Prajapati




