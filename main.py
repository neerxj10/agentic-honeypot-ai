# ==========================================================
# AGENTIC HONEYPOT API – FINAL STABLE VERSION
# GUVI + Render + Postman SAFE
# ==========================================================

import re
import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse

app = FastAPI(title="Agentic Honeypot API")

# ==========================================================
# 🔐 API KEY (hardcoded → simplest + safest for hackathon)
# ==========================================================
API_KEY = "teamkranusapikey123"

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# ==========================================================
# MEMORY STORE
# ==========================================================
sessions = {}


# ==========================================================
# AUTH
# ==========================================================
def verify_api_key(x_api_key: str | None):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


# ==========================================================
# SCAM KEYWORDS
# ==========================================================
SCAM_KEYWORDS = [
    "account blocked", "verify", "urgent", "otp",
    "upi", "bank", "suspended", "click", "link"
]


def detect_scam(text: str):
    text = text.lower()
    return any(k in text for k in SCAM_KEYWORDS)


# ==========================================================
# INTEL EXTRACTION
# ==========================================================
def empty_intel():
    return {
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


def extract_intel(text: str, intel: dict):

    text_low = text.lower()

    intel["upiIds"] += re.findall(r"\b[\w.-]+@[\w.-]+\b", text)
    intel["phishingLinks"] += re.findall(r"http[s]?://\S+|www\.\S+", text)
    intel["phoneNumbers"] += re.findall(r"(?:\+91[- ]?)?[6-9]\d{4}[- ]?\d{5}", text)
    intel["bankAccounts"] += re.findall(r"\b\d{12,18}\b", text)
    intel["emailAddresses"] += re.findall(r"\b[\w.-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text)
    intel["amounts"] += re.findall(r"(?:₹|rs\.?|inr)?\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?", text_low)
    intel["otpCodes"] += re.findall(r"\b\d{4,6}\b(?=\s*(?:otp|code|pin))", text_low)
    intel["cardNumbers"] += re.findall(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", text)
    intel["ifscCodes"] += re.findall(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", text)

    for k in SCAM_KEYWORDS:
        if k in text_low:
            intel["suspiciousKeywords"].append(k)

    # remove duplicates
    for key in intel:
        intel[key] = list(set(intel[key]))

    return intel


# ==========================================================
# AGENT REPLY LOGIC
# ==========================================================
def agent_reply(text: str):

    text = text.lower()

    if "upi" in text:
        return "I’m not very good with UPI, can you guide me step by step?"
    if "otp" in text:
        return "Why do you need my OTP? Is it safe?"
    if "link" in text:
        return "Is this an official bank link?"
    if "account" in text:
        return "Why is my account being blocked suddenly?"

    return "Can you explain again?"


# ==========================================================
# CALLBACK TO GUVI
# ==========================================================
def send_final_callback(session_id, session):

    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": len(session["messages"]),
        "extractedIntelligence": session["intel"],
        "agentNotes": "Honeypot triggered"
    }

    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
        print("✅ Callback sent")
    except Exception as e:
        print("⚠ Callback failed:", e)


# ==========================================================
# MAIN ENDPOINT
# ==========================================================
@app.post("/honeypot")
async def honeypot(request: Request, x_api_key: str = Header(None)):

    verify_api_key(x_api_key)

    data = await request.json()

    # health check for tester
    if not data:
        return {"status": "alive"}

    session_id = data.get("sessionId", "default")

    msg_obj = data.get("message", {})
    message = msg_obj.get("text", "")
    sender = msg_obj.get("sender", "user")

    # create session safely
    if session_id not in sessions:
        sessions[session_id] = {
            "messages": [],
            "intel": empty_intel()
        }

    session = sessions[session_id]

    session["messages"].append({"sender": sender, "text": message})

    if detect_scam(message):

        session["intel"] = extract_intel(message, session["intel"])

        reply = agent_reply(message)

        session["messages"].append({"sender": "agent", "text": reply})

        if len(session["messages"]) >= 10:
            send_final_callback(session_id, session)

        return {"status": "success", "reply": reply}

    return {"status": "ignored", "reply": "Okay"}


# ==========================================================
# ROOT
# ==========================================================
@app.get("/")
def root():
    return HTMLResponse("<h2>🕵️ Honeypot running securely</h2>")
