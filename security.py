from fastapi import FastAPI
from pydantic import BaseModel
import re
import hashlib
import requests
import json
from datetime import datetime


# ============================================================
# CREATE FASTAPI APP
# ============================================================

app = FastAPI(
    title="Email Security & Forensics API"
)


# ============================================================
# INPUT FORMAT
# ============================================================

class EmailRequest(BaseModel):
    email: str
    threat_status: str = "Dangerous"


# ============================================================
# ANALYZE EMAIL
# ============================================================

@app.post("/analyze")
def analyze_email(request: EmailRequest):

    email = request.email

    # --------------------------------------------------------
    # 1. EXTRACT IP ADDRESS
    # --------------------------------------------------------

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    ip_matches = re.findall(ip_pattern, email)

    if ip_matches:
        sender_ip = ip_matches[0]
    else:
        sender_ip = "IP Not Found"


    # --------------------------------------------------------
    # 2. IP GEOLOCATION
    # --------------------------------------------------------

    location = {
        "city": "Unknown",
        "country": "Unknown",
        "latitude": None,
        "longitude": None
    }

    if sender_ip != "IP Not Found":

        try:

            api_url = f"http://ip-api.com/json/{sender_ip}"

            response = requests.get(
                api_url,
                timeout=10
            )

            data = response.json()

            if data.get("status") == "success":

                location["city"] = data.get(
                    "city",
                    "Unknown"
                )

                location["country"] = data.get(
                    "country",
                    "Unknown"
                )

                location["latitude"] = data.get("lat")

                location["longitude"] = data.get("lon")

        except Exception:

            pass


    # --------------------------------------------------------
    # 3. SHA-256 HASH
    # --------------------------------------------------------

    email_hash = hashlib.sha256(
        email.encode("utf-8")
    ).hexdigest()


    # --------------------------------------------------------
    # 4. TIMESTAMP
    # --------------------------------------------------------

    timestamp = datetime.now().isoformat()


    # --------------------------------------------------------
    # 5. CREATE FORENSIC REPORT
    # --------------------------------------------------------

    forensic_report = {

        "email_id": "EMAIL-001",

        "threat_status": request.threat_status,

        "sender_ip": sender_ip,

        "location": {

            "city": location["city"],

            "country": location["country"],

            "latitude": location["latitude"],

            "longitude": location["longitude"]
        },

        "evidence": {

            "sha256": email_hash,

            "timestamp": timestamp,

            "integrity": "VERIFIED"
        }
    }


    # --------------------------------------------------------
    # 6. SAVE REPORT
    # --------------------------------------------------------

    with open(
        "forensic_report.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            forensic_report,
            file,
            indent=4
        )


    # --------------------------------------------------------
    # 7. RETURN RESULT TO BACKEND
    # --------------------------------------------------------

    return forensic_report  
