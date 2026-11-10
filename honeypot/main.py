from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, Response
import logging
import json
from datetime import datetime
import requests

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

logging.basicConfig(
    filename="cisco_attacks.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

BANK_TELEMETRY_URL = "http://127.0.0.1:8000/api/v1/telemetry/receive"

def forward_telemetry(payload: dict):
    try:
        requests.post(BANK_TELEMETRY_URL, json=payload, timeout=1)
    except Exception:
        pass

CISCO_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cisco Systems - Device Manager</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; }
        body { background-color: #0d2738; display: flex; justify-content: center; align-items: center; height: 100vh; color: #333; }
        .login-card { background: #ffffff; width: 420px; border-radius: 4px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); overflow: hidden; }

        .header { background: #0088ce; padding: 24px 28px; color: white; display: flex; flex-direction: column; align-items: flex-start; }
        .logo-container { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
        .logo-bridge { display: inline-flex; gap: 2px; align-items: flex-end; height: 18px; }
        .logo-bridge span { background-color: #ffffff; width: 3px; border-radius: 1px; }
        .logo-text { font-weight: 700; font-size: 20px; letter-spacing: -0.5px; color: #ffffff; }
        .header h1 { font-size: 16px; font-weight: 400; letter-spacing: 0.3px; color: #ffffff; line-height: 1.3; }

        .form-body { padding: 30px; }
        .alert-box { background: #fdf2f2; border-left: 4px solid #d9534f; color: #b52b27; padding: 10px 14px; font-size: 13px; margin-bottom: 20px; display: none; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; color: #555; }
        .form-group input { width: 100%; padding: 10px 12px; border: 1px solid #ccc; border-radius: 3px; font-size: 14px; outline: none; }
        .form-group input:focus { border-color: #0088ce; }
        .btn-submit { width: 100%; background: #0088ce; color: white; border: none; padding: 12px; font-size: 14px; font-weight: 600; border-radius: 3px; cursor: pointer; }
        .btn-submit:hover { background: #006699; }
        .footer { background: #f4f6f8; padding: 15px 30px; border-top: 1px solid #e1e6eb; text-align: center; font-size: 11px; color: #777; }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="header">
            <div class="logo-container">
                <div class="logo-bridge">
                    <span style="height: 8px;"></span>
                    <span style="height: 13px;"></span>
                    <span style="height: 18px;"></span>
                    <span style="height: 13px;"></span>
                    <span style="height: 18px;"></span>
                    <span style="height: 13px;"></span>
                    <span style="height: 8px;"></span>
                </div>
                <span class="logo-text">cisco</span>
            </div>
            <h1>RV340 Gigabit Dual WAN VPN Router</h1>
        </div>
        <div class="form-body">
            <div id="errorMsg" class="alert-box">Invalid username or password. Please try again.</div>
            <form action="/api/v1/auth/login" method="POST">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" autocomplete="off" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" autocomplete="off" required>
                </div>
                <button type="submit" class="btn-submit">Log In</button>
            </form>
        </div>
        <div class="footer">
            &copy; 1992-2026 Cisco Systems, Inc. All rights reserved.
        </div>
    </div>
    <script>
        if (window.location.search.includes('err=auth_failed')) {
            document.getElementById('errorMsg').style.display = 'block';
        }
    </script>
</body>
</html>"""

@app.middleware("http")
async def apply_cisco_headers(request: Request, call_next):
    client_ip = request.headers.get("X-Forwarded-For", request.client.host)
    log_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": client_ip,
        "method": request.method,
        "path": str(request.url.path),
        "user_agent": request.headers.get("user-agent", "Unknown")
    }
    logging.info(f"PROBE DETECTED: {json.dumps(log_data)}")
    forward_telemetry(log_data)

    response: Response = await call_next(request)
    response.headers["Server"] = "Cisco-HTTP-1.1"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response

@app.get("/", response_class=HTMLResponse)
async def root_redirect():
    return RedirectResponse(url="/api/v1/auth/login.html", status_code=302)

@app.get("/api/v1/auth/login.html", response_class=HTMLResponse)
async def get_login_page():
    return HTMLResponse(content=CISCO_LOGIN_HTML)

@app.post("/api/v1/auth/login")
async def handle_login(request: Request, username: str = Form(...), password: str = Form(...)):
    client_ip = request.headers.get("X-Forwarded-For", request.client.host)
    cred_log = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": client_ip,
        "username": username,
        "password": password,
        "path": str(request.url.path),
        "user_agent": request.headers.get("user-agent", "Unknown")
    }
    logging.info(f"CREDENTIAL CAPTURED: {json.dumps(cred_log)}")
    forward_telemetry(cred_log)
    return RedirectResponse(url="/api/v1/auth/login.html?err=auth_failed", status_code=302)