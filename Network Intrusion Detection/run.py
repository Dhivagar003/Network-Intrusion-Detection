"""
run.py — entry point for the NIDS Flask application.
Usage:
    python run.py
"""
import sys
import os

# Ensure project root is on path so "backend.*" imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app import app
from backend.config import PORT, DEBUG

if __name__ == "__main__":
    print(f"\nNIDS Agent running at http://0.0.0.0:{PORT}")
    print(f"Local access:         http://127.0.0.1:{PORT}")
    print(f"Network access:       http://<your-ip>:{PORT}")
    print("Press Ctrl+C to stop.\n")
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG, use_reloader=False)
