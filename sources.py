
import re
import requests

def is_valid_ioc(ioc: str) -> bool:
    url_pattern = re.compile(r'^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$')
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    domain_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    return bool(url_pattern.match(ioc) or ip_pattern.match(ioc) or domain_pattern.match(ioc))

def detect_ioc_type(ioc: str) -> str:
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
        return "ip"
    else:
        return "domain"

def query_whois(ioc: str) -> dict:
    return {
        "source": "WHOIS",
        "verdict": "Informational",
        "risk_score": 10,
        "raw_data": {
            "target": ioc,
            "status": "Active domain / IP query completed",
            "registrar": "Public Registry Check"
        }
    }

def query_virustotal(ioc: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}
    ioc_type = detect_ioc_type(ioc)
    
    try:
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        else:
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            risk_score = min(100, (malicious * 15) + (suspicious * 5))
            verdict = "Malicious" if malicious > 0 else ("Suspicious" if suspicious > 0 else "Clean")
            
            return {
                "source": "VirusTotal",
                "verdict": verdict,
                "risk_score": risk_score,
                "raw_data": stats
            }
        else:
            return {
                "source": "VirusTotal",
                "verdict": "API Error",
                "risk_score": 0,
                "raw_data": {"error": f"HTTP {response.status_code}"}
            }
    except Exception as e:
        return {
            "source": "VirusTotal",
            "verdict": "Error",
            "risk_score": 0,
            "raw_data": {"error": str(e)}
        }

SOURCES = {
    "WHOIS": query_whois,
    "VirusTotal": query_virustotal
}
