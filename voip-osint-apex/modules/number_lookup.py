# pyrefly: ignore [missing-import]
import phonenumbers
# pyrefly: ignore [missing-import]
from phonenumbers import geocoder, carrier, timezone
# pyrefly: ignore [missing-import]
import requests
import os
from dotenv import load_dotenv

load_dotenv()
IPQS_KEY = os.getenv("IPQS_KEY")
NUMVERIFY_KEY = os.getenv("NUMVERIFY_KEY")

def analyze_number(number: str) -> dict:
    result = {
        "number": number,
        "country": "Unknown",
        "carrier": "Unknown",
        "timezone": "Unknown",
        "valid": False,
        "line_type": "Unknown",
        "fraud_score": 0,
        "disposable": False,
        "active": False,
        "vpn": False,
        "tor": False,
        "leaked": False,
        "recent_abuse": False,
        "risk_level": "LOW",
        "risk_reason": "No high risk indicators found"
    }
    
    try:
        parsed = phonenumbers.parse(number)
        result["country"] = geocoder.description_for_number(parsed, "en") or result["country"]
        result["carrier"] = carrier.name_for_number(parsed, "en") or result["carrier"]
        tz = timezone.time_zones_for_number(parsed)
        result["timezone"] = tz[0] if tz else result["timezone"]
        result["valid"] = phonenumbers.is_valid_number(parsed)
        num_type = phonenumbers.number_type(parsed)
        if num_type == phonenumbers.PhoneNumberType.MOBILE: result["line_type"] = "mobile"
        elif num_type == phonenumbers.PhoneNumberType.FIXED_LINE: result["line_type"] = "fixed"
        elif num_type == phonenumbers.PhoneNumberType.VOIP: result["line_type"] = "voip"
    except Exception as e:
        pass

    if IPQS_KEY and IPQS_KEY != "your_key":
        try:
            r = requests.get(f"https://www.ipqualityscore.com/api/json/phone/{IPQS_KEY}/{number}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get("success"):
                    result["fraud_score"] = data.get("fraud_score", 0)
                    result["disposable"] = data.get("VOIP", False) or data.get("disposable", False)
                    result["active"] = data.get("active", False)
                    result["line_type"] = data.get("line_type", result["line_type"])
                    result["vpn"] = data.get("vpn", False)
                    result["tor"] = data.get("tor", False)
                    result["recent_abuse"] = data.get("recent_abuse", False)
                    result["leaked"] = data.get("leaked", False)
                    if data.get("carrier"):
                        result["carrier"] = data.get("carrier")
        except:
            pass

    if NUMVERIFY_KEY and NUMVERIFY_KEY != "your_key":
        try:
            r = requests.get(f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}&number={number}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                if "valid" in data:
                    result["valid"] = data["valid"]
                    result["country"] = data.get("country_name", result["country"])
                    result["carrier"] = data.get("carrier", result["carrier"])
                    result["line_type"] = data.get("line_type", result["line_type"])
        except:
            pass

    try:
        r = requests.get("https://dan.me.uk/torlist/", timeout=5)
        if r.status_code == 200:
            pass
    except:
        pass

    score = result["fraud_score"]
    if score > 85:
        result["risk_level"] = "CRITICAL"
        result["risk_reason"] = "Extremely high fraud score"
    elif score > 75:
        result["risk_level"] = "HIGH"
        result["risk_reason"] = "High fraud score"
    elif score > 40:
        result["risk_level"] = "MEDIUM"
        result["risk_reason"] = "Medium fraud score"
    
    if result["tor"]:
        result["risk_level"] = "CRITICAL"
        result["risk_reason"] += " (Tor connection)"

    return result
