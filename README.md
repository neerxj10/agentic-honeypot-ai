# Agentic Honeypot for Scam Detection

## Overview
This project implements an AI-powered agentic honeypot that detects scam intent, engages scammers autonomously, extracts scam intelligence, and reports final results to the GUVI evaluation endpoint.

## Features
- Scam intent detection
- Autonomous human-like AI agent
- Multi-turn conversation handling using sessionId
- Intelligence extraction (UPI IDs, links, phone numbers, keywords)
- Mandatory final callback to GUVI
- API key–secured REST API

## API Endpoint
POST /honeypot

Headers:
- x-api-key: YOUR_SECRET_API_KEY
- Content-Type: application/json

## Final Callback
Once sufficient engagement is completed, the system sends a final JSON payload to:
https://hackathon.guvi.in/api/updateHoneyPotFinalResult