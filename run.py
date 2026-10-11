"""
Runner script for BANKISM — AI Banking Security Firewall.
Intelligently binds to an available port (8000, 8080, 8001, etc.)
and serves the complete frontend and API.
"""

import socket
import sys
import uvicorn


def find_available_port(preferred_ports=(8000, 8080, 8001, 8002, 8888)):
    for port in preferred_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return 8000


if __name__ == "__main__":
    port = find_available_port()
    print("=" * 70)
    print("   BANKISM — AI Banking Security Firewall & Live Attack Lab")
    print("   Defensive Architecture: Attack -> Analyze -> Defend -> Gate -> Verify")
    print("=" * 70)
    print(f" * Serving UI and API at: http://127.0.0.1:{port}")
    print(f" * API Documentation at:  http://127.0.0.1:{port}/docs")
    print(" * Independent Verifier:  ACTIVE")
    print(" * Operating Mode:        Rule-Based Fallback (Optional LLM enabled via .env)")
    print("=" * 70)
    uvicorn.run("backend.main:app", host="127.0.0.1", port=port, log_level="info")
