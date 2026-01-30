# ==========================================
# AGENTIC HONEYPOT API (FINAL – GUVI SAFE)
# ==========================================

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional, Dict
import os
import re
import requests
from dotenv import load_dotenv

# ==========================================
# LOAD ENV
# ==========================================
load_dotenv()

API_KEY = os.getenv("HONEYPOT_API_KEY")  # ✅ secure (Render env)
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# ==========================================
# APP INIT
# ==========================================
app = FastAPI(title="Agentic Honeypot API")

# ==========================================
# MEMORY STORE
# ==========================================
sessions = {}

# ==========================================
# SCHEMAS (optional only)
# ==========================================
class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[str] = ""


class RequestBody(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[Dict] = {}


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


def detect_scam(text: str) -> bool:
    text = text.lower()
    return any(k in text for k in SCAM_KEYWORDS)


# ==========================================
# INTEL EXTRACTION
# ==========================================
def extract_intel(text: str, intel: dict):
    text_low = text.lower()

    intel["upiIds"].extend(re.findall(r"\w+@\w+", text))
    intel["phishingLinks"].extend(re.findall(r"http[s]?://\S+", text))
    intel["phoneNumbers"].extend(re.findall(r"\+91\d{10}", text))

    for k in SCAM_KEYWORDS:
        if k in text_low and k not in intel["suspiciousKeywords"]:
            intel["suspiciousKeywords"].append(k)

    return intel


# ==========================================
# AGENT REPLY
# ==========================================
def agent_reply(last_text: str):
    last_text = last_text.lower()

    if "upi" in last_text:
        return "I’m not very good with UPI, can you guide me step by step?"

    if "account" in last_text:
        return "Why is my account being blocked suddenly?"

    if "link" in last_text:
        return "Is this an official bank link? I’m a bit scared to click."

    return "Sorry, I didn’t understand properly. Can you explain again?"


# ==========================================
# FINAL CALLBACK
# ==========================================
def send_final_callback(session_id, session):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": len(session["messages"]),
        "extractedIntelligence": session["intelligence"],
        "agentNotes": "Used urgency and UPI redirection tactics"
    }

    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
        print("✅ FINAL CALLBACK SENT")
    except Exception as e:
        print("❌ Callback failed:", e)


# ==========================================
# MAIN ENDPOINT (IMPORTANT FIX HERE)
# ==========================================
@app.post("/honeypot")
async def honeypot(
    request: Request,
    x_api_key: str = Header(...)
):
    """
    ✅ Works with:
       - empty body (GUVI tester)
       - real body (actual honeypot usage)
    """

    verify_api_key(x_api_key)

    # Try reading JSON safely
    try:
        data = await request.json()
    except:
        data = {}

    # --------------------------------------
    # CASE 1: Tester (no body)
    # --------------------------------------
    if not data:
        return {"status": "alive"}

    # --------------------------------------
    # CASE 2: Real honeypot request
    # --------------------------------------
    body = RequestBody(**data)

    session = sessions.setdefault(body.sessionId, {
        "messages": [],
        "intelligence": {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": []
        },
        "scamConfirmed": False
    })

    session["messages"].append({
        "sender": body.message.sender,
        "text": body.message.text
    })

    is_scam = detect_scam(body.message.text)

    if is_scam:
        session["scamConfirmed"] = True
        session["intelligence"] = extract_intel(
            body.message.text,
            session["intelligence"]
        )

        reply = agent_reply(body.message.text)

        session["messages"].append({
            "sender": "agent",
            "text": reply
        })

        if len(session["messages"]) >= 10 and not session.get("finalSent"):
            send_final_callback(body.sessionId, session)
            session["finalSent"] = True

        return {"status": "success", "reply": reply}

    return {"status": "ignored", "reply": "Okay"}


# ==========================================
# ROOT PAGE
# ==========================================
@app.get("/")
def root():
    return HTMLResponse("<h2>🕵️ Agentic Honeypot API is running</h2>")
