from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict
import re
import requests

# ==============================
# CONFIG
# ==============================
import os

API_KEY = os.getenv("HONEYPOT_API_KEY", "dev-secret-key")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# ==============================
# APP INIT
# ==============================
app = FastAPI(title="Agentic Honeypot API")

# ==============================
# MEMORY STORE (In-Memory)
# ==============================
sessions = {}

# ==============================
# SCHEMA
# ==============================
class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class RequestBody(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[Dict] = {}

# ==============================
# AUTH
# ==============================
def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

# ==============================
# SCAM DETECTOR
# ==============================
SCAM_KEYWORDS = [
    "account blocked", "verify", "urgent", "upi",
    "bank", "otp", "suspended", "click", "link"
]

def detect_scam(text: str) -> bool:
    text = text.lower()
    return any(k in text for k in SCAM_KEYWORDS)

# ==============================
# INTELLIGENCE EXTRACTION
# ==============================
def extract_intel(text: str, intel: dict):
    text_low = text.lower()

    if "upi" in text_low:
        intel["upiIds"].extend(re.findall(r"\w+@\w+", text))

    intel["phishingLinks"].extend(re.findall(r"http[s]?://\S+", text))
    intel["phoneNumbers"].extend(re.findall(r"\+91\d{10}", text))

    for k in SCAM_KEYWORDS:
        if k in text_low and k not in intel["suspiciousKeywords"]:
            intel["suspiciousKeywords"].append(k)

    return intel

# ==============================
# AGENT (Human-like replies)
# ==============================
def agent_reply(last_text: str):
    last_text = last_text.lower()

    if "upi" in last_text:
        return "I’m not very good with UPI, can you guide me step by step?"

    if "account" in last_text:
        return "Why is my account being blocked suddenly?"

    if "link" in last_text:
        return "Is this an official bank link? I’m a bit scared to click."

    return "Sorry, I didn’t understand properly. Can you explain again?"

# ==============================
# FINAL CALLBACK
# ==============================
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
        print("✅ FINAL CALLBACK SENT TO GUVI")
    except Exception as e:
        print("❌ Callback failed:", e)

# ==============================
# MAIN ENDPOINT
# ==============================
@app.post("/honeypot")
def honeypot(body: RequestBody, x_api_key: str = Header(...)):
    verify_api_key(x_api_key)

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

    # Save incoming message
    session["messages"].append({
        "sender": body.message.sender,
        "text": body.message.text
        
    })
    print("📩 Total messages so far:", len(session["messages"]))


    # Detect scam
    is_scam = detect_scam(body.message.text)

    if is_scam:
        session["scamConfirmed"] = True
        session["intelligence"] = extract_intel(
            body.message.text,
            session["intelligence"]
        )

        reply = agent_reply(body.message.text)

        session["messages"].append({
            "sender": "user",
            "text": reply
        })

        # FINAL CALLBACK after enough engagement
        print("🔥 Trigger check:", len(session["messages"]))
        

        
        if len(session["messages"]) >= 10 and not session.get("finalSent"):
            send_final_callback(body.sessionId, session)
            session["finalSent"] = True


        return {
            "status": "success",
            "reply": reply
        }

    return {
        "status": "ignored",
        "reply": "Okay"
    }
from fastapi.responses import HTMLResponse

@app.get("/")
def root():
    return HTMLResponse("""
    <html>
        <head>
            <title>Agentic Honeypot API</title>
        </head>
        <center>
        <body style="font-family: Arial; padding: 40px;">
            <h1>🕵️ Agentic Honeypot API</h1>
            <p>This is a backend API service for scam detection and intelligence extraction.</p>

            <h3>Usage</h3>
            <center>
            <ul style="list-style-type: none; padding: 0;">
                <li><b>Endpoint:</b> <code>/honeypot</code></li>
                <li><b>Method:</b> POST</li>
                <li><b>Authentication:</b> x-api-key header</li>
                <li><b>Content-Type:</b> application/json</li>
            </ul>
            </center>

            <p>This service is designed for machine-to-machine communication and does not provide a user interface.</p>
            <p><b>Thank you for using the Agentic Honeypot API!</b></p> 
            </center>           
        </body>
    </html>
    """)

