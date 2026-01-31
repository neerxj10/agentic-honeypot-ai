# ==========================================
# AGENTIC HONEYPOT API (GUVI + RENDER SAFE)
# ==========================================

import os
import re
import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse

# ==========================================
# ENV (Render provides automatically)
# ==========================================
API_KEY = os.getenv("HONEYPOT_API_KEY")

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

app = FastAPI(title="Agentic Honeypot API")

# ==========================================
# MEMORY STORE
# ==========================================
sessions = {}

# ==========================================
# AUTH
# ==========================================
def verify_api_key(x_api_key: str):
    if not API_KEY or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")


# ==========================================
# SCAM DETECTOR
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
def extract_intel(text, intel):
    text_low = text.lower()

    intel["upiIds"] += re.findall(r"\b[\w.-]+@[\w.-]+\b", text)

    intel["phishingLinks"] += re.findall(r"http[s]?://\S+|www\.\S+", text)

    intel["phoneNumbers"] += re.findall(r"(?:\+91[- ]?)?[6-9]\d{4}[- ]?\d{5}", text)

    intel["bankAccounts"] += re.findall(r"\b\d{12,18}\b", text)

    for k in SCAM_KEYWORDS:
        if k in text_low and k not in intel["suspiciousKeywords"]:
            intel["suspiciousKeywords"].append(k)

    return intel


# ==========================================
# AGENT REPLY
# ==========================================
def agent_reply(text):
    text = text.lower()

    if "upi" in text:
        return "I’m not very good with UPI, can you guide me step by step?"
    if "account" in text:
        return "Why is my account being blocked suddenly?"
    if "link" in text:
        return "Is this an official bank link? I’m scared to click."
    if "otp" in text:
        return "Why do you need my OTP? Isn’t that private?"
    if "verify" in text:
        return "What will happen if I don’t verify right now?"
    if "urgent" in text:
        return "Why is this urgent? Can it wait?"
    if "suspended" in text:
        return "How long will my account be suspended?"
    if "click" in text:
        return "I’m not comfortable clicking links from unknown sources."
    if "bank" in text:
        return "Can you tell me more about this bank issue?"
    if "blocked" in text:
        return "What should I do to unblock my account?"
    if "suspend" in text:
        return "Will my account be suspended permanently?"

    return "Can you explain again?"


# ==========================================
# CALLBACK
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
        print("Callback sent")
    except:
        pass


# ==========================================
# MAIN ENDPOINT (GUVI SAFE)
# ==========================================
@app.post("/honeypot")
async def honeypot(request: Request, x_api_key: str = Header(...)):

    
    verify_api_key(x_api_key)

    
    try:
        data = await request.json()
    except:
        data = {}

    # ----------------------------------
    # TESTER MODE (empty body)
    # ----------------------------------
    if not data:
        return {"status": "alive"}


    # ----------------------------------
    # REAL HONEYPOT MODE
    # ----------------------------------
    session_id = data.get("sessionId", "default")
    message = data.get("message", {}).get("text", "")
    sender = data.get("message", {}).get("sender", "user")

    session = sessions.setdefault(session_id, {
        "messages": [],
        "intel": {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": []
        }
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
    return HTMLResponse("<h2>🕵️ Honeypot running</h2>")