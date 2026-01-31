# ==========================================
# AGENTIC HONEYPOT API (FINAL - GUVI + RENDER SAFE)
# ==========================================

import os
import re
import requests
from collections import defaultdict
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse

# ==========================================
# ENV (SECURE)
# ==========================================
API_KEY = os.getenv("HONEYPOT_API_KEY")

# Fail fast if ENV missing (prevents ACCESS_ERROR confusion)
if not API_KEY:
    raise RuntimeError(
        "❌ HONEYPOT_API_KEY not set. Add it in Render → Environment Variables"
    )

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

app = FastAPI(title="Agentic Honeypot API")

# ==========================================
# MEMORY STORE
# ==========================================
sessions = {}

# ==========================================
# AUTH
# ==========================================
def verify_api_key(x_api_key: str | None):
    if x_api_key is None:
        raise HTTPException(status_code=401, detail="Missing API key")

    if x_api_key.strip() != API_KEY.strip():
        raise HTTPException(status_code=401, detail="Invalid API key")


# ==========================================
# SCAM KEYWORDS
# ==========================================
SCAM_KEYWORDS = [
    "account blocked", "verify", "urgent", "upi",
    "bank", "otp", "suspended", "click", "link"
]


def detect_scam(text: str):
    text = text.lower()
    return any(k in text for k in SCAM_KEYWORDS)


# ==========================================
# INTEL EXTRACTION
# ==========================================
def extract_intel(text: str, intel: dict):

    text_low = text.lower()

    intel["upiIds"] += re.findall(r"\b[\w.-]+@[\w.-]+\b", text)

    intel["phishingLinks"] += re.findall(r"http[s]?://\S+|www\.\S+", text)

    intel["phoneNumbers"] += re.findall(
        r"(?:\+91[- ]?)?[6-9]\d{4}[- ]?\d{5}", text
    )

    intel["bankAccounts"] += re.findall(r"\b\d{12,18}\b", text)

    intel["amounts"] += re.findall(
        r"(?:₹|rs\.?|inr)?\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?",
        text_low
    )

    intel["otpCodes"] += re.findall(
        r"\b\d{4,6}\b(?=\s*(?:otp|code|pin))",
        text_low
    )

    intel["cardNumbers"] += re.findall(
        r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        text
    )

    intel["ifscCodes"] += re.findall(
        r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        text
    )

    # suspicious keywords
    for k in SCAM_KEYWORDS:
        if k in text_low:
            intel["suspiciousKeywords"].append(k)

    # dedupe all lists
    for k in intel:
        intel[k] = list(set(intel[k]))

    return intel


# ==========================================
# AGENT REPLY LOGIC
# ==========================================
def agent_reply(text):

    text = text.lower()

    if "upi" in text:
        return "I’m not very good with UPI, can you guide me step by step?"
    if "otp" in text:
        return "Why do you need my OTP? Is it safe?"
    if "link" in text:
        return "Is this an official bank link?"
    if "account" in text:
        return "Why is my account being blocked suddenly?"
    if "verify" in text:
        return "What details do I need to verify?"

    return "Can you explain again?"


# ==========================================
# CALLBACK TO GUVI
# ==========================================
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
    except:
        print("⚠ Callback failed")


# ==========================================
# MAIN ENDPOINT (GUVI COMPATIBLE)
# ==========================================
@app.post("/honeypot")
async def honeypot(request: Request, x_api_key: str = Header(None)):

    verify_api_key(x_api_key)

    try:
        data = await request.json()
    except:
        data = {}

    # Tester health check
    if not data:
        return {"status": "alive"}

    session_id = data.get("sessionId", "default")
    message = data.get("message", {}).get("text", "")
    sender = data.get("message", {}).get("sender", "user")

    # Create session safely
    session = sessions.setdefault(session_id, {
        "messages": [],
        "intel": defaultdict(list)
    })

    session["messages"].append({"sender": sender, "text": message})

    if detect_scam(message):

        session["intel"] = extract_intel(message, session["intel"])

        reply = agent_reply(message)

        session["messages"].append({"sender": "agent", "text": reply})

        if len(session["messages"]) >= 10:
            send_final_callback(session_id, session)

        return {"status": "success", "reply": reply}

    return {"status": "ignored", "reply": "Okay"}


# ==========================================
# ROOT
# ==========================================
@app.get("/")
def root():
    return HTMLResponse("<h2>🕵️ Honeypot running securely</h2>")