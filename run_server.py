#!/usr/bin/env python3
"""
Kavach-Guard: Gateway Server Launcher
Starts the FastAPI backend at http://0.0.0.0:8000
"""

import uvicorn
import os

if __name__ == "__main__":
    print("=" * 70)
    print("    KAVACH-GUARD: LAKERA-STYLE AI AGENT & RAG SECURITY GATEWAY")
    print("=" * 70)
    print("Server running on: http://127.0.0.1:8000")
    print("API Docs:          http://127.0.0.1:8000/docs")
    print("Lakera Guard API:  POST http://127.0.0.1:8000/v2/guard")
    print("RAG Security Gate: POST http://127.0.0.1:8000/v2/inspect_rag")
    print("Attack Simulator:  POST http://127.0.0.1:8000/v2/simulate_attack")
    print("Research Data:     GET  http://127.0.0.1:8000/api/benchmark/table")
    print("WebSocket Stream:  ws://127.0.0.1:8000/ws/telemetry")
    print("=" * 70)
    uvicorn.run("kavach_guard.server:app", host=os.getenv("KAVACH_HOST", "127.0.0.1"),
                port=int(os.getenv("KAVACH_PORT", "8000")), reload=False)
