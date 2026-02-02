#!/usr/bin/env python3
"""Simple HTTP server for the AgentTrust web demo."""
import http.server
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))
print("🛡️  AgentTrust Web Demo — http://localhost:8080")
http.server.HTTPServer(("", 8080), http.server.SimpleHTTPRequestHandler).serve_forever()
