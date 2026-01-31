# ==========================================================
# AGENTIC HONEYPOT – FINAL GUARANTEED VERSION
# GUVI + Render + Postman SAFE
# Single file only
# ==========================================================

import re
from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Agentic Honeypot API")


# ==========================================================
# 🔐 API KEY (hardcoded – simplest)
# ==========================================================
API_KEY = "teamkranusapikey123"


# ==========================================================
# SCAM KEYWORDS
# ==========================================================
SCAM_KEYWORDS = [
    "otp", "urgent", "verify", "blocked",
    "account", "click", "link", "transfer",
    "refund", "kyc", "bank"
]


# ==========================================================
# INTEL EXTRACTION
# ==========================================================
def extract_intel(text: str):

    text_low = text.lower()

    intel = {
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "bankAccounts": [],
        "emailAddresses": [],
        "amounts": [],
        "otpCodes": [],
        "cardNumbers": [],
        "ifscCodes": [],
        "suspiciousKeywords": []
    }

    # UPI
    intel["upiIds"] += re.findall(r"\b[\w.-]+@[\w.-]+\b", text)

    # URLs
    intel["phishingLinks"] += re.findall(r"http[s]?://\S+|www\.\S+", text)

    # Phones
    intel["phoneNumbers"] += re.findall(r"(?:\+91[- ]?)?[6-9]\d{4}[- ]?\d{5}", text)

    # Bank accounts
    intel["bankAccounts"] += re.findall(r"\b\d{12,18}\b", text)

    # Emails
    intel["emailAddresses"] += re.findall(
        r"\b[\w.-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text
    )

    # Amounts
    intel["amounts"] += re.findall(
        r"(?:₹|rs\.?|inr)?\s?\d+(?:,\d{3})*(?:\.\d{2})?", text_low
    )

    # OTP
    intel["otpCodes"] += re.findall(
        r"\b\d{4,6}\b(?=\s*(otp|code|pin))", text_low
    )

    # Cards
    intel["cardNumbers"] += re.findall(
        r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", text
    )

    # IFSC
    intel["ifscCodes"] += re.findall(
        r"\b[A-Z]{4}0[A-Z0-9]{6}\b", text
    )

    # Suspicious keywords
    for k in SCAM_KEYWORDS:
        if k in text_low:
            intel["suspiciousKeywords"].append(k)

    # remove duplicates
    for key in intel:
        intel[key] = list(set(intel[key]))

    return intel


# ==========================================================
# MAIN ENDPOINT (EXACT FORMAT GUVI NEEDS)
# ==========================================================
@app.post("/honeypot")
async def honeypot(data: dict, x_api_key: str = Header(None)):

    # AUTH CHECK
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # message may come as string or object
    message = ""

    if isinstance(data.get("message"), str):
        message = data["message"]
    elif isinstance(data.get("message"), dict):
        message = data["message"].get("text", "")

    intel = extract_intel(message)

    # IMPORTANT: THIS EXACT KEY IS REQUIRED
    return {
        "extractedIntelligence": intel
    }


# ==========================================================
# ROOT
# ==========================================================
@app.get("/")
def root():
    return {"status": "Honeypot running 🚀"}
