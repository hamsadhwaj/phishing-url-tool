
import re
import requests
import whois
from datetime import datetime
from urllib.parse import urlparse

def analyze_url(url):
    results={}
    
    if not url.startswith(('http://','https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc

    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    is_ip = bool(re.match(ip_pattern, domain))
    results['is_ip_address'] = {
        'detected' : is_ip,
        'risk' : 'HIGH' if is_ip else 'LOW',
        'message' : 'Domain is an IP address (phishing sites often use IPs)' if is_ip else 'Domain is not an IP address'
    }

    has_at = "@" in url
    results['has_at_symbol'] = {
        'detected' : has_at,
        'risk' : 'HIGH' if has_at else 'LOW',
        'message' : '@ symbol found (can hide real domain)' if has_at else 'No @ symbol detected'
    }

    has_hyphen = "-" in url
    results['has_hyphen'] = {
        'detected' : has_hyphen,
        'risk' : 'HIGH' if has_hyphen else 'LOW',
        'message' : 'Hyphens in domain (often used to mimic legitimate sites)' if has_hyphen else 'No hyphens in domain'
    }

    is_https = parsed.scheme == "https"
    results['is_https'] = {
        'detected' : is_https,
        'risk' : 'LOW' if is_https else 'HIGH',
        'message' : 'Site uses HTTPS encryption' if is_https else 'Site does not use HTTPS encrption (unencrypted connection)'
    }

    
    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        has_mailto = "mailto:" in response.text.lower()
        mailto_count = response.text.lower().count("mailto:")
        results['has_mailto'] = {
            'detected' : has_mailto,
            'risk' : 'MEDIUM' if has_mailto else 'LOW',
            'message' : f'mailto links found ({mailto_count} instances) - may collect emails' if has_mailto else 'No mailto links detected',
            'count' : mailto_count
        }
    except requests.RequestException as e:
        results['has_mailto'] = {
        'detected' : None,
        'risk' : 'UNKNOWN',
        'message' : f'Could not fetch page content {str(e)[:50]}'
    }
        
    
    try:
        w=whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            age_days = (datetime.now()-creation_date).days
            age_years = age_days/365.25
            is_new = age_days<180

            if age_days<30:
                risk_level = 'HIGH' 
            elif age_days<180:
                risk_level = 'MEDIUM'
            else: risk_level = 'LOW'

            results['domain_age'] = {
            'detected' : is_new,
            'risk' : risk_level,
            'message' : f'Domain is {age_days} days old ({int(age_years)}years) - {"Very new domain (suspicious)" if is_new else "Established Domain"}'
    }
        else:
            results['domain_age'] = {
            'detected' : None,
            'risk' : 'UNKNOWN',
            'message' : 'Domain age could not be determined',
            'age_days' : None,
            'creation_date' : 'UNKNOWN'
            }
    except Exception as e:
        results['domain_age'] = {
        'detected' : None,
        'risk' : 'UNKNOWN',
        'message' : f'Error retreiving WHOIS data: {str(e)[:50]}',
        'age_days' : None,
        'Creation_date' : 'Error'
        }
    return results

def calculate_risk_score(results):
    score=0
    max_score=0
    risk_weights={
        'HIGH':3,
        'MEDIUM':2,
        'LOW':0,
        'UNKNOWN':0
    }

    for indicator, data in results.items():
        if isinstance(data, dict) and 'risk' in data:
            max_score+=3
            score+=risk_weights.get(data['risk'],0)
    
    percent=(score/max_score*100) if max_score>0 else 0

    if percent>=60:
        return percent,"HIGH risk - Likely Phishing Site"
    elif percent>=30:
        return percent,"MEDIUM risk - Exercise Caution"
    else: return percent, "LOW risk - Appears Legitimate"

def print_report(url, results):
    print("\n"+"="*70)
    print(f"{'Phishing analysis report:'}")
    print("="*70)
    print(f"\nTarget URL: {url}\n")
    print("-"*70)

    risk_icons={
        'HIGH': '[!]',
        'MEDIUM' : '[~]',
        'LOW' : '[+]',
        'UNKNOWN' : '❓'
    }

    for indicator, data in results.items():
        if isinstance(data, dict):
            icon=risk_icons.get(data['risk'],'.')
            # indicator_name=indicator.replace('_',' ').title()
            friendly_names={
                'is_ip_address':'Suspicious IP address',
                'has_at_symbol':'Hidden redirect symbol (@)',
                'has_hyphen':'Suspicious Domain in Name',
                'is_https':'Secure connection (HTTPS)',
                'has_mailto':'Email collection Links',
                'domain_age':'Website Age'
            }
            indicator_name=friendly_names.get(indicator, indicator.replace('_',' ').title())
            print(f"\n{icon} {indicator_name}")
            print(f"Risk Level: {data['risk']}")
            print(f"Details: {data['message']}")

    print("\n"+"-"*70)

    risk_percent, risk_assessment=calculate_risk_score(results)
    print(f"\n{'OVERALL RISK ASSESSMENT':^70}")
    print(f"Risk Score: {int(risk_percent)}%".center(70))
    print(f"{risk_assessment:^70}")
    print("\n" + "="*70)


if __name__=="__main__":
    print("Phishing URL Scanner")
    # print("Enter the URL")

    targer_url=input("Enter the URL to scan: ").strip()

    if not targer_url:
        print("Error - no URL provided")
    else: 
        print("Analyzing URL please wait...")
        report=analyze_url(targer_url)
        print_report(targer_url, report)
