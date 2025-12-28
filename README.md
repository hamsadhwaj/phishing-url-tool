# 🎣 Phishing URL Scanner

A Python-based tool that analyzes URLs to detect potential phishing indicators. This script performs static and dynamic analysis on a given URL to calculate a risk score, helping users identify suspicious websites.

## 🚀 Features

This tool performs the following checks to assess the safety of a URL:

* **IP Address Detection**: Checks if the domain is a raw IP address (common in phishing).
* **URL Obfuscation Check**: Detects the `@` symbol used to hide true destinations.
* **Typosquatting Detection**: flags excessive use of hyphens in domain names.
* **Protocol Security**: Verifies if the site uses HTTPS.
* **Content Analysis**: Scrapes the page for `mailto:` links (often used for email harvesting).
* **Domain Age Verification**: Uses WHOIS data to check if the domain is suspiciously new (less than 6 months old).
* **Risk Scoring**: Calculates an overall risk percentage and categorizes the URL as **LOW**, **MEDIUM**, or **HIGH** risk.

## 🛠️ Prerequisites

* Python 3.x
* Internet connection (for WHOIS lookups and page scraping)

## 📦 Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/your-repo-name.git](https://github.com/your-username/your-repo-name.git)
    cd your-repo-name
    ```

2.  **Install required Python packages:**
    You need to install `requests` and `python-whois` (which allows the `import whois` used in the script).
    
    ```bash
    pip install requests python-whois
    ```
    *(Note: Ensure you install `python-whois` and not just `whois`, as they are different packages.)*

## 💻 Usage

1.  Run the script:
    ```bash
    python phishing_scanner.py
    ```
    *(Replace `phishing_scanner.py` with your actual filename if different)*

2.  Enter the URL you want to scan when prompted:
    ```text
    Enter the URL to scan: [http://suspicious-bank-login.com](http://suspicious-bank-login.com)
    ```

## 📋 Example Output

```text
======================================================================
Phishing analysis report:
======================================================================

Target URL: [http://example-phishing-site.com](http://example-phishing-site.com)

----------------------------------------------------------------------

[+] Suspicious IP address
Risk Level: LOW
Details: Domain is not an IP address

[!] Secure connection (HTTPS)
Risk Level: HIGH
Details: Site does not use HTTPS encryption (unencrypted connection)

[~] Website Age
Risk Level: MEDIUM
Details: Domain is 45 days old (0 years) - Very new domain (suspicious)

----------------------------------------------------------------------

                       OVERALL RISK ASSESSMENT                        
                           Risk Score: 65%                            
                  HIGH risk - Likely Phishing Site                    

======================================================================
