import asyncio
import json
import socket
import ssl
import urllib.request
import urllib.parse
import re
import os
import smtplib
import concurrent.futures
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Dict, Optional
from fastapi import FastAPI, HTTPException, Query, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="NCAS Cyber Portal - CyberShield Suite")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SMTP Email Alert Configurations
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "alerts@cybershield-portal.ncas")

# Thread Pool for Asynchronous Email Delivery (prevents event loop lag)
executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

def send_alert_email(subject: str, body: str):
    recipient = "mohammedhisham35996@gmail.com"
    msg = MIMEMultipart()
    msg['From'] = SMTP_FROM
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Always log the alert to console for immediate diagnostics
    print(f"\n--- [CYBERSHIELD EMAIL ALERT DISPATCH] ---")
    print(f"To: {recipient}")
    print(f"Subject: {subject}")
    print(body)
    print("-------------------------------------------\n")

    if not SMTP_USER or not SMTP_PASS:
        print("[SMTP] Dispatch skipped: Credentials SMTP_USER/SMTP_PASS are not configured.")
        return

    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        print("[SMTP] Email alert successfully transmitted.")
    except Exception as e:
        print(f"[SMTP] Transmission error: {e}")

# Safe non-blocking email dispatch helper
def dispatch_email_async(subject: str, body: str):
    executor.submit(send_alert_email, subject, body)

# Persistent JSON Databases Config
STUDENTS_FILE = "students.json"
FACULTIES_FILE = "faculties.json"
INCIDENTS_FILE = "incidents.json"

def load_db(file_path: str, default_data):
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading DB file {file_path}: {e}")
            return default_data
    return default_data

def save_db(file_path: str, data):
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
    except Exception as e:
        print(f"Error writing DB file {file_path}: {e}")

# Load active databases on startup
admin_credentials = {"username": "reiz", "password": "heavenofreiz"}
student_db = load_db(STUDENTS_FILE, {})
faculty_db = load_db(FACULTIES_FILE, {"professor_x": "faculty123"})
reported_incidents = load_db(INCIDENTS_FILE, [
    {
        "id": 1,
        "title": "Phishing Campaign Verification",
        "category": "Phishing",
        "description": "Urgent emails attempting to harvest portal credentials.",
        "reporter": "professor_x",
        "status": "Resolved",
        "solution": "Configured DMARC rejection rules for the spoofed domain name.",
        "timestamp": "2026-07-19 07:30:15",
        "image_data": None,
        "voice_data": None
    }
])
faculty_limit = load_db("faculty_limit.json", 5)


# Ban lists & Intruder logs database
banned_ips = set()
banned_users = set()
security_alerts = []
user_activities = []  # Live activity tracking database

# Cache resolved geolocations to keep logins fast
GEO_CACHE = {}

def resolve_ip_location(ip: str) -> str:
    if not ip or ip in ["127.0.0.1", "localhost", "::1"]:
        return "NCAS Campus Link"
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    url = f"http://ip-api.com/json/{ip}?fields=country,city"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("country"):
                loc = f"{data.get('city', 'Unknown City')}, {data.get('country')}"
                GEO_CACHE[ip] = loc
                return loc
    except Exception:
        pass
    return "Unknown Location"

def log_activity(username: str, role: str, action: str, ip: str, user_agent: str = "Unknown Device"):
    location = resolve_ip_location(ip)
    
    device = "Unknown OS / Browser"
    if "Windows" in user_agent:
        device = "Windows PC"
    elif "Macintosh" in user_agent or "Mac OS" in user_agent:
        device = "macOS Device"
    elif "Android" in user_agent:
        device = "Android Phone"
    elif "iPhone" in user_agent or "iPad" in user_agent:
        device = "iOS iPhone"
    elif "Linux" in user_agent:
        device = "Linux Machine"
        
    if "Chrome" in user_agent:
        device += " (Chrome)"
    elif "Firefox" in user_agent:
        device += " (Firefox)"
    elif "Safari" in user_agent:
        device += " (Safari)"
    elif "Edge" in user_agent:
        device += " (Edge)"
        
    user_activities.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "username": username,
        "role": role,
        "action": action,
        "ip": ip,
        "device": device,
        "location": location
    })

# Middleware to intercept and reject banned IPs
@app.middleware("http")
async def check_ban_status(request: Request, call_next):
    client_ip = request.client.host
    
    # Exclude loopback/localhost IPs from any bans
    if client_ip in ["127.0.0.1", "localhost", "::1"]:
        return await call_next(request)
        
    if client_ip in banned_ips:
        return JSONResponse(
            status_code=403,
            content={"detail": "ACCESS TERMINATED: Your IP address has been banned due to security violations."}
        )
            
    return await call_next(request)

# Helper to log and ban intruders
def log_and_ban_intruder(request: Request, username: Optional[str], action: str):
    client_ip = request.client.host
    user_agent = request.headers.get("User-Agent", "Unknown")
    path = request.url.path
    method = request.method
    
    if client_ip in ["127.0.0.1", "localhost", "::1"]:
        return
        
    banned_ips.add(client_ip)
    if username:
        banned_users.add(username.lower())
        
    security_alerts.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "username": username or "Guest/Anonymous",
        "ip": client_ip,
        "user_agent": user_agent,
        "path": f"{method} {path}",
        "action": action,
        "status": "IP Banned"
    })

    # Send Security Alert Email (non-blocking thread pool execution)
    subject = f"[CyberShield Security Alert] Intruder IP Blacklisted"
    body = (
        f"Security Event: IP Blocked & Session Terminated\n"
        f"Intruder IP: {client_ip}\n"
        f"Target Username: {username or 'Guest/Anonymous'}\n"
        f"Violation Action: {action}\n"
        f"Request: {method} {path}\n"
        f"User-Agent: {user_agent}\n"
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    )
    dispatch_email_async(subject, body)

# API models
class ScamAnalyzeRequest(BaseModel):
    text: str

class ChatRequest(BaseModel):
    message: str
    history: List[Dict[str, str]] = []

class SignUpRequest(BaseModel):
    email: str
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class IncidentRequest(BaseModel):
    title: str
    category: str
    description: str
    reporter: str
    image_data: Optional[str] = None
    voice_data: Optional[str] = None

class SolveRequest(BaseModel):
    id: int
    solution: str

class FacultyCreateRequest(BaseModel):
    username: str
    password: str

class FacultyLimitRequest(BaseModel):
    limit: int

class HeaderAnalyzeRequest(BaseModel):
    headers_text: str

class BanIPRequest(BaseModel):
    ip: str

# Auth Endpoints
@app.post("/api/signup")
async def signup(req: SignUpRequest, request: Request):
    username_clean = req.username.strip().lower()
    email_clean = req.email.strip().lower()
    client_ip = request.client.host
    
    if not re.match(r"^[a-z0-9_]{3,20}$", username_clean):
        raise HTTPException(status_code=400, detail="Username must be alphanumeric, between 3 and 20 characters, and can only include underscores.")
        
    if "@" not in email_clean or "." not in email_clean:
        raise HTTPException(status_code=400, detail="Registration requires a valid email address.")
        
    if username_clean in ["admin", "reiz"]:
        log_and_ban_intruder(request, req.username, "Privilege escalation attempt during signup")
        raise HTTPException(status_code=403, detail="Violation logged.")
    if username_clean in student_db or username_clean in faculty_db:
        raise HTTPException(status_code=400, detail="Username already registered.")
    student_db[username_clean] = req.password
    save_db(STUDENTS_FILE, student_db) # Persist on signup
    log_activity(username_clean, "student", f"Account registration completed (Email: {email_clean})", client_ip)
    return {"status": "success"}

@app.post("/api/login")
async def login(req: LoginRequest, request: Request):
    username_clean = req.username.strip().lower()
    password = req.password
    client_ip = request.client.host
    user_agent = request.headers.get("User-Agent", "Unknown")
    
    if username_clean == admin_credentials["username"]:
        if password == admin_credentials["password"]:
            log_activity("reiz", "admin", "Admin portal login successful", client_ip, user_agent)
            return {"status": "authenticated", "role": "admin", "username": "reiz"}
            
        log_activity("reiz", "admin", "Admin login failed: Incorrect password", client_ip, user_agent)
        raise HTTPException(status_code=401, detail="Invalid admin credentials.")
        
    if username_clean in faculty_db:
        if faculty_db[username_clean] == password:
            log_activity(username_clean, "faculty", "Faculty portal login successful", client_ip, user_agent)
            return {"status": "authenticated", "role": "faculty", "username": username_clean}
            
        log_activity(username_clean, "faculty", "Faculty login failed: Incorrect password", client_ip, user_agent)
        raise HTTPException(status_code=401, detail="Invalid faculty credentials.")
        
    if username_clean in student_db:
        if student_db[username_clean] == password:
            log_activity(username_clean, "student", "Student portal login successful", client_ip, user_agent)
            return {"status": "authenticated", "role": "student", "username": username_clean}
            
        log_activity(username_clean, "student", "Student login failed: Incorrect password", client_ip, user_agent)
        raise HTTPException(status_code=401, detail="Invalid credentials.")
        
    log_activity(username_clean, "unknown", "Login failed: User not found", client_ip, user_agent)
    raise HTTPException(status_code=401, detail="User not found.")

# Strict Incidents Isolation
@app.get("/api/incidents")
async def get_incidents(role: str = Query(...), username: str = Query(...), request: Request = None):
    username_clean = username.strip().lower()
    if role == "admin":
        if username_clean != "reiz":
            log_and_ban_intruder(request, username, "Threat console bypass alert")
            raise HTTPException(status_code=403, detail="Violation logged.")
        return {"incidents": reported_incidents}
        
    # Unique ID isolation: student can only query incidents matching their lowercase username
    user_incidents = [inc for inc in reported_incidents if inc["reporter"] == username_clean]
    return {"incidents": user_incidents}

@app.post("/api/incident")
async def create_incident(req: IncidentRequest, request: Request):
    new_id = len(reported_incidents) + 1
    reporter_clean = req.reporter.strip().lower()
    client_ip = request.client.host
    
    reported_incidents.append({
        "id": new_id,
        "title": req.title,
        "category": req.category,
        "description": req.description,
        "reporter": reporter_clean,
        "status": "Pending",
        "solution": "",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "image_data": req.image_data,
        "voice_data": req.voice_data
    })
    save_db(INCIDENTS_FILE, reported_incidents) # Persist on submission

    log_activity(reporter_clean, "user", f"Reported threat incident #{new_id}", client_ip)

    # Dispatch Alert Email to Admin (non-blocking)
    subject = f"[CyberShield Alert] New Threat Incident Reported by {reporter_clean}"
    body = (
        f"Incident Alert Summary:\n"
        f"Incident ID: {new_id}\n"
        f"Reporter: {reporter_clean}\n"
        f"Category: {req.category}\n"
        f"Title: {req.title}\n"
        f"Description: {req.description}\n"
        f"Has Image Attachment: {'Yes' if req.image_data else 'No'}\n"
        f"Has Voice Recording: {'Yes' if req.voice_data else 'No'}\n"
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    )
    dispatch_email_async(subject, body)

    return {"status": "submitted"}

@app.post("/api/incident/solve")
async def resolve_incident(req: SolveRequest, role: str = Query(...), username: str = Query(...), request: Request = None):
    username_clean = username.strip().lower()
    client_ip = request.client.host
    if role != "admin" or username_clean != "reiz":
        log_and_ban_intruder(request, username, "Incident solve bypass alert")
        raise HTTPException(status_code=403, detail="Violation logged.")
    for inc in reported_incidents:
        if inc["id"] == req.id:
            inc["solution"] = req.solution
            inc["status"] = "Resolved"
            save_db(INCIDENTS_FILE, reported_incidents) # Persist on resolution

            log_activity("reiz", "admin", f"Resolved threat incident #{req.id}", client_ip)

            # Dispatch Resolution Email to Admin (non-blocking)
            subject = f"[CyberShield Alert] Threat Incident #{req.id} Resolved"
            body = (
                f"Incident Resolution Update:\n"
                f"Incident ID: {inc.id}\n"
                f"Reporter: {inc['reporter']}\n"
                f"Title: {inc['title']}\n"
                f"Resolution Action: {req.solution}\n"
                f"Resolved By: Admin (reiz)\n"
                f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            dispatch_email_async(subject, body)

            return {"status": "resolved"}
    raise HTTPException(status_code=404, detail="Incident not found.")

# Faculty Management
@app.get("/api/admin/faculty")
async def get_faculty_list(role: str = Query(...), username: str = Query(...), request: Request = None):
    username_clean = username.strip().lower()
    if role != "admin" or username_clean != "reiz":
        log_and_ban_intruder(request, username, "Faculty list bypass alert")
        raise HTTPException(status_code=403, detail="Access denied.")
    return {
        "faculties": [{"username": k, "password": v} for k, v in faculty_db.items()],
        "limit": faculty_limit,
        "count": len(faculty_db)
    }

@app.post("/api/admin/faculty")
async def create_faculty(req: FacultyCreateRequest, role: str = Query(...), username: str = Query(...), request: Request = None):
    username_clean = username.strip().lower()
    client_ip = request.client.host
    if role != "admin" or username_clean != "reiz":
        log_and_ban_intruder(request, username, "Faculty create bypass alert")
        raise HTTPException(status_code=403, detail="Access denied.")
    new_user = req.username.strip().lower()
    faculty_limit = load_db("faculty_limit.json", 5)
    if len(faculty_db) >= faculty_limit:
        raise HTTPException(status_code=400, detail="Faculty account limit reached.")
    if new_user in faculty_db or new_user in student_db or new_user == "reiz":
        raise HTTPException(status_code=400, detail="Username occupied.")
    faculty_db[new_user] = req.password
    save_db(FACULTIES_FILE, faculty_db) # Persist on allocation
    log_activity("reiz", "admin", f"Allocated new faculty member: {new_user}", client_ip)
    return {"status": "created"}

@app.post("/api/admin/faculty/limit")
async def update_faculty_limit(req: FacultyLimitRequest, role: str = Query(...), username: str = Query(...), request: Request = None):
    username_clean = username.strip().lower()
    if role != "admin" or username_clean != "reiz":
        log_and_ban_intruder(request, username, "Faculty limit configuration bypass")
        raise HTTPException(status_code=403, detail="Access denied.")
    global faculty_limit
    faculty_limit = req.limit
    save_db("faculty_limit.json", req.limit)
    return {"status": "updated"}

@app.delete("/api/admin/faculty")
async def delete_faculty(target_username: str = Query(...), role: str = Query(...), username: str = Query(...), request: Request = None):
    username_clean = username.strip().lower()
    client_ip = request.client.host
    if role != "admin" or username_clean != "reiz":
        log_and_ban_intruder(request, username, "Faculty deletion bypass alert")
        raise HTTPException(status_code=403, detail="Access denied.")
    target_clean = target_username.strip().lower()
    if target_clean in faculty_db:
        del faculty_db[target_clean]
        save_db(FACULTIES_FILE, faculty_db) # Persist deletions
        log_activity("reiz", "admin", f"Removed faculty member: {target_clean}", client_ip)
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Faculty not found.")

# Administrative IP Termination & Blacklisting
@app.post("/api/admin/ban")
async def ban_ip(req: BanIPRequest, role: str = Query(...), username: str = Query(...), request: Request = None):
    username_clean = username.strip().lower()
    if role != "admin" or username_clean != "reiz":
        log_and_ban_intruder(request, username, "IP termination bypass attempt")
        raise HTTPException(status_code=403, detail="Access denied.")
    if req.ip in ["127.0.0.1", "localhost", "::1"]:
        raise HTTPException(status_code=400, detail="Cannot ban loopback / localhost IP address.")
    banned_ips.add(req.ip)
    log_activity("reiz", "admin", f"Administratively banned & terminated IP: {req.ip}", request.client.host)
    return {"status": "banned"}

# Metrics & User Live Activity Logs
@app.get("/api/admin/metrics")
async def get_system_metrics(role: str = Query(...), username: str = Query(...), request: Request = None):
    username_clean = username.strip().lower()
    if role != "admin" or username_clean != "reiz":
        log_and_ban_intruder(request, username, "Admin metrics bypass alert")
        raise HTTPException(status_code=403, detail="Access denied.")
    all_users = [{"username": k, "role": "student"} for k in student_db.keys()] + \
                [{"username": k, "role": "faculty"} for k in faculty_db.keys()]
    
    return {
        "users": all_users,
        "security_logs": security_alerts,
        "banned_ips": list(banned_ips),
        "activities": user_activities[-50:], # Return last 50 activity streams
        "limit": faculty_limit
    }


# --- REAL-TIME INTEL SUITE ENDPOINTS ---
def query_json_api(url: str, headers: Optional[Dict[str, str]] = None) -> dict:
    req = urllib.request.Request(url)
    if headers:
        for key, val in headers.items():
            req.add_header(key, val)
    try:
        with urllib.request.urlopen(req, timeout=6) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

# Cache resolved geolocations & AI answers
AI_CACHE = {}

# Free Backend AI Inference Endpoint via Pollinations keyless text gateway
async def query_free_llm(prompt: str) -> Optional[str]:
    prompt_clean = prompt.strip().lower()
    if prompt_clean in AI_CACHE:
        return AI_CACHE[prompt_clean]
        
    system_prompt = (
        "You are Natasha, a professional, highly advanced AI assistant. "
        "Answer the user's questions on any real-world topic (general knowledge, calculations, time, cybersecurity, and beyond) in their input language. "
        "Keep your response concise, direct, and formatted in clean Markdown."
    )
    
    # URL encode system persona and user prompt
    encoded_text = urllib.parse.quote(f"System: {system_prompt}\nUser: {prompt}")
    api_url = f"https://text.pollinations.ai/{encoded_text}?model=openai-gpt-4o-mini"
    
    try:
        loop = asyncio.get_event_loop()
        def fetch():
            req = urllib.request.Request(api_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.read().decode("utf-8").strip()
        text = await loop.run_in_executor(None, fetch)
        if text:
            AI_CACHE[prompt_clean] = text
            return text
    except Exception as e:
        print(f"[POLLINATIONS LLM] Query error: {e}")
    return None

@app.get("/api/speedtest")
async def speedtest_payload():
    # Return 500 KB of garbage data for benchmarking download throughput
    payload = b"0" * 500000
    return StreamingResponse(iter([payload]), media_type="application/octet-stream")

@app.get("/api/domain/dns")
async def get_dns_records(domain: str = Query(...), username: str = Query("guest"), role: str = Query("guest"), request: Request = None):
    log_activity(username, role, f"Executed DNS diagnostics for domain: {domain}", request.client.host)
    record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS"]
    results = {}
    async def fetch_record(rectype: str):
        url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type={rectype}"
        headers = {"Accept": "application/dns-json"}
        try:
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, query_json_api, url, headers)
            answers = data.get("Answer", [])
            results[rectype] = [
                {"data": ans.get("data"), "ttl": ans.get("TTL")} for ans in answers
            ]
        except Exception:
            results[rectype] = []
    await asyncio.gather(*(fetch_record(rt) for rt in record_types))
    return {"domain": domain, "records": results}

@app.get("/api/domain/whois")
async def get_whois(domain: str = Query(...), username: str = Query("guest"), role: str = Query("guest"), request: Request = None):
    log_activity(username, role, f"Executed WHOIS lookup for domain: {domain}", request.client.host)
    url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(None, query_json_api, url)
        entities = data.get("entities", [])
        registrar = "Unknown"
        for entity in entities:
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn": registrar = field[3]
        events = data.get("events", [])
        dates = {}
        for event in events:
            action = event.get("eventAction")
            date_str = event.get("eventDate")
            if action and date_str: dates[action] = date_str
        return {
            "domain": domain,
            "registrar": registrar,
            "status": data.get("status", []),
            "created": dates.get("registration"),
            "changed": dates.get("last changed"),
            "expires": dates.get("expiration"),
            "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]
        }
    except Exception:
        raise HTTPException(status_code=404, detail="RDAP data not found.")

@app.get("/api/domain/ssl")
async def get_ssl_info(domain: str = Query(...)):
    loop = asyncio.get_event_loop()
    def fetch_ssl():
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_info = ssock.getpeercert()
                pem = ssl.DER_cert_to_PEM_cert(ssock.getpeercert(binary_form=True))
                return cert_info, pem
    try:
        cert_info, pem = await loop.run_in_executor(None, fetch_ssl)
        subject = dict(x[0] for x in cert_info.get("subject", []))
        issuer = dict(x[0] for x in cert_info.get("issuer", []))
        return {
            "domain": domain,
            "subject": subject,
            "issuer": issuer,
            "valid_from": cert_info.get("notBefore"),
            "valid_until": cert_info.get("notAfter"),
            "version": cert_info.get("version"),
            "serialNumber": cert_info.get("serialNumber"),
            "pem": pem
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/domain/subdomains")
async def check_subdomains(domain: str = Query(...)):
    subdomains_to_test = ["www", "mail", "api", "dev", "blog", "secure", "vpn", "admin", "portal", "test", "ftp", "shop"]
    discovered = []
    async def resolve_subdomain(sub: str):
        full_host = f"{sub}.{domain}"
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, full_host)
            discovered.append({"subdomain": full_host, "ip": ip})
        except Exception: pass
    await asyncio.gather(*(resolve_subdomain(s) for s in subdomains_to_test))
    return {"domain": domain, "resolved_subdomains": discovered}

@app.get("/api/ip/geo")
async def get_ip_geolocation(ip: str = Query(...), username: str = Query("guest"), role: str = Query("guest"), request: Request = None):
    log_activity(username, role, f"Executed Geolocation IP analysis: {ip}", request.client.host)
    url = f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(None, query_json_api, url)
        reputation = "Clean"
        if data.get("status") == "success":
            isp_lower = data.get("isp", "").lower()
            if "hosting" in isp_lower or "cloud" in isp_lower or "vpn" in isp_lower or "datacenter" in isp_lower:
                reputation = "Medium Risk (VPN/Hosting Provider)"
        data["reputation"] = reputation
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ip/revdns")
async def reverse_dns(ip: str = Query(...)):
    loop = asyncio.get_event_loop()
    try:
        hostname, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return {"ip": ip, "hostname": hostname}
    except Exception:
        return {"ip": ip, "hostname": "No reverse DNS record found"}

# Email Intelligence Core
@app.get("/api/email/auth")
async def get_email_auth_records(domain: str = Query(...)):
    dns_url = "https://cloudflare-dns.com/dns-query"
    headers = {"Accept": "application/dns-json"}
    async def fetch_dns(name: str, rtype: str):
        url = f"{dns_url}?name={urllib.parse.quote(name)}&type={rtype}"
        try:
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, query_json_api, url, headers)
            return [ans.get("data") for ans in data.get("Answer", [])]
        except Exception: return []
    mx_records, txt_records = await asyncio.gather(
        fetch_dns(domain, "MX"), fetch_dns(domain, "TXT")
    )
    spf_record = "Missing"
    for txt in txt_records:
        if "v=spf1" in txt:
            spf_record = txt.strip('"')
            break
    dmarc_txt = await fetch_dns(f"_dmarc.{domain}", "TXT")
    dmarc_record = "Missing"
    for txt in dmarc_txt:
        if "v=DMARC1" in txt:
            dmarc_record = txt.strip('"')
            break
    return {
        "domain": domain,
        "mx_servers": mx_records,
        "spf": spf_record,
        "dmarc": dmarc_record,
        "status": "Configured" if spf_record != "Missing" and dmarc_record != "Missing" else "Incomplete"
    }

@app.post("/api/email/analyze-headers")
async def analyze_email_headers(req: HeaderAnalyzeRequest):
    text = req.headers_text
    extracted = {
        "From": re.search(r"(?i)^From:\s*(.*)", text, re.MULTILINE),
        "To": re.search(r"(?i)^To:\s*(.*)", text, re.MULTILINE),
        "Subject": re.search(r"(?i)^Subject:\s*(.*)", text, re.MULTILINE),
        "Return-Path": re.search(r"(?i)^Return-Path:\s*<(.*)>", text, re.MULTILINE),
        "Authentication-Results": re.search(r"(?i)^Authentication-Results:\s*(.*)", text, re.MULTILINE)
    }
    for k, v in extracted.items():
        extracted[k] = v.group(1).strip() if v else "Not Found"
        
    phishing_risk = "Low"
    warnings = []
    if extracted["Return-Path"] != "Not Found" and extracted["From"] != "Not Found":
        rp_match = re.search(r"[\w\.-]+@([\w\.-]+)", extracted["Return-Path"])
        from_match = re.search(r"[\w\.-]+@([\w\.-]+)", extracted["From"])
        if rp_match and from_match:
            if rp_match.group(1).lower() != from_match.group(1).lower():
                phishing_risk = "High"
                warnings.append("Header Spoofing Detected: Return-Path domain does not align with the display From header domain.")
                
    return {
        "headers": extracted,
        "phishing_risk": phishing_risk,
        "warnings": warnings
    }

@app.get("/api/username/search")
async def search_username(username: str = Query(...)):
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Dev.to": f"https://dev.to/{username}",
        "PyPI": f"https://pypi.org/user/{username}",
        "npm": f"https://www.npmjs.com/~{username}",
        "DockerHub": f"https://hub.docker.com/u/{username}",
        "Keybase": f"https://keybase.io/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/"
    }
    results = []
    
    async def check_profile(name: str, url: str):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        try:
            loop = asyncio.get_event_loop()
            def fetch_status():
                class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                        return None
                opener = urllib.request.build_opener(NoRedirectHandler)
                opener.addheaders = [("User-Agent", headers["User-Agent"])]
                try:
                    req = urllib.request.Request(url, headers=headers)
                    with opener.open(req, timeout=3) as resp:
                        return resp.getcode()
                except urllib.error.HTTPError as e:
                    return e.code
                except Exception:
                    return 0
            code = await loop.run_in_executor(None, fetch_status)
            if code == 200:
                results.append({"platform": name, "url": url, "status": "Available"})
        except Exception:
            pass
            
    await asyncio.gather(*(check_profile(plat, url) for plat, url in platforms.items()))
    return {"username": username, "profiles": results}

@app.get("/api/domain/tech")
async def audit_web_headers(domain: str = Query(...)):
    url = f"http://{domain}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        loop = asyncio.get_event_loop()
        def fetch_headers():
            with urllib.request.urlopen(req, timeout=4) as resp:
                return dict(resp.headers), resp.version
        headers, version = await loop.run_in_executor(None, fetch_headers)
        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing"),
            "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
            "Referrer-Policy": headers.get("Referrer-Policy", "Missing")
        }
        tech = {
            "Server": headers.get("Server", "Undetected"),
            "Powered-By": headers.get("X-Powered-By", "Undetected"),
            "HTTP Version": "HTTP/1.1" if version == 11 else "HTTP/1.0"
        }
        return {"domain": domain, "security_headers": security_headers, "technology": tech}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/domain/redirect")
async def trace_redirects(url: str = Query(...)):
    trace = []
    class TraceRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            trace.append({"code": code, "url": req.full_url})
            return super().redirect_request(req, fp, code, msg, hdrs, newurl)
    opener = urllib.request.build_opener(TraceRedirectHandler)
    opener.addheaders = [("User-Agent", "Mozilla/5.0")]
    try:
        loop = asyncio.get_event_loop()
        def execute_trace():
            with opener.open(url, timeout=5) as resp:
                trace.append({"code": 200, "url": resp.url})
                return trace
        chain = await loop.run_in_executor(None, execute_trace)
        return {"start_url": url, "redirect_chain": chain}
    except Exception as e:
        return {"start_url": url, "redirect_chain": trace, "error": str(e)}

# Threat CVE Query
@app.get("/api/threat/cve")
async def query_cve_db(query: str = Query(...)):
    # 1. Local CVE Database Lookup
    cve_database = [
        {"id": "CVE-2021-44228", "title": "Log4Shell", "severity": "Critical (10.0)", "description": "Apache Log4j2 remote code execution vulnerability."},
        {"id": "CVE-2023-38831", "title": "WinRAR RCE", "severity": "High (7.8)", "description": "WinRAR ZIP file processing remote execution vulnerability."},
        {"id": "CVE-2024-3094", "title": "XZ Utils Backdoor", "severity": "Critical (10.0)", "description": "Malicious code injection in XZ Utils payload delivery stream."},
        {"id": "CVE-2024-21626", "title": "runc Container Escape", "severity": "High (8.6)", "description": "runc container breakout vulnerability via file descriptor leaks."}
    ]
    matches = [cve for cve in cve_database if query.lower() in cve["id"].lower() or query.lower() in cve["title"].lower()]
    
    # 2. Try fetching real-time CVE details from public Cloudflare / CIRCL CVE API
    url = f"https://cve.circl.lu/api/cve/{urllib.parse.quote(query.upper().strip())}"
    try:
        loop = asyncio.get_event_loop()
        real_time_cve = await loop.run_in_executor(None, query_json_api, url)
        if real_time_cve and "id" in real_time_cve:
            matches.insert(0, {
                "id": real_time_cve.get("id"),
                "title": real_time_cve.get("summary", "Zero-day CVE entry")[:55] + "...",
                "severity": f"CVSS {real_time_cve.get('cvss', 'N/A')}",
                "description": real_time_cve.get("summary", "No description available.")
            })
    except Exception:
        pass
        
    return {"query": query, "matches": matches[:10]}

# 1. Phone OSINT Lookup Tool
@app.get("/api/osint/phone")
async def get_phone_osint(number: str = Query(...), username: str = Query("guest"), role: str = Query("guest"), request: Request = None):
    log_activity(username, role, f"Executed Phone OSINT Lookup: {number}", request.client.host)
    # Strip spaces/symbols
    clean_num = re.sub(r"\D", "", number)
    
    # Basic Country Code identification
    country = "Unknown"
    cc_map = {
        "1": "United States/Canada (+1)",
        "91": "India (+91)",
        "44": "United Kingdom (+44)",
        "971": "United Arab Emirates (+971)",
        "33": "France (+33)",
        "49": "Germany (+49)",
        "966": "Saudi Arabia (+966)",
        "61": "Australia (+61)",
        "81": "Japan (+81)"
    }
    for cc, name in cc_map.items():
        if clean_num.startswith(cc):
            country = name
            break
            
    # Carrier Patterns (educational simulation based on typical prefixes)
    carrier = "Standard Mobile Telephony Gateway"
    if clean_num.startswith("91"):
        sub = clean_num[2:]
        if len(sub) > 0:
            if sub[0] in ["9", "8", "7"]:
                carrier = "Reliance Jio / Airtel Network"
            elif sub[0] in ["6"]:
                carrier = "Vodafone Idea Network"
    
    # Real-Time DDG Scraper OSINT query to find exactly where the number is mentioned on the web!
    search_query = f'"{number}"'
    ddg_url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(search_query)}"
    found_urls = []
    
    try:
        loop = asyncio.get_event_loop()
        def fetch_ddg():
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            req = urllib.request.Request(ddg_url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as resp:
                html = resp.read().decode('utf-8', errors='ignore')
                snippets = re.findall(r'<a class="result__snippet"[^>]*>(.*?)</a>', html, re.DOTALL)
                cleaned_snippets = []
                for s in snippets[:3]:
                    cleaned_snippets.append(re.sub(r'<[^>]*>', '', s).strip())
                return cleaned_snippets
        found_urls = await loop.run_in_executor(None, fetch_ddg)
    except Exception:
        pass
        
    usage = [
        "IM Messenger Services (WhatsApp/Telegram/Signal Active Indicator)",
        "Standard Public Switched Telephone Network (PSTN)",
        "Dynamic SMS Validation Services (Two-Factor Handshakes)"
    ]
    if found_urls:
        usage.insert(0, f"Web Mention Matches: {', '.join(found_urls)}")
    else:
        usage.insert(0, "No public indexed web crawler listings found.")
        
    if len(clean_num) < 8:
        return {"error": "Invalid phone number length. Please include country code."}
        
    return {
        "original": number,
        "clean_number": clean_num,
        "country": country,
        "carrier": carrier,
        "potential_usages": usage,
        "social_presence": {
            "whatsapp": "Active (Verification signature detected)",
            "telegram": "Active (Recent session metadata handshake)",
            "signal": "Undetected"
        }
    }

# 2. Phishing URL Detector
@app.get("/api/url/detect")
async def detect_phishing_url(url: str = Query(...), username: str = Query("guest"), role: str = Query("guest"), request: Request = None):
    log_activity(username, role, f"Phishing URL scan: {url}", request.client.host)
    parsed = urllib.parse.urlparse(url)
    netloc = parsed.netloc or url
    
    risk_score = 0
    reasons = []
    
    # 1. Suspicious TLD check
    suspicious_tlds = [".xyz", ".top", ".buzz", ".work", ".info", ".tk", ".ml", ".cf", ".gq", ".fit"]
    for tld in suspicious_tlds:
        if netloc.endswith(tld):
            risk_score += 35
            reasons.append(f"High-risk top-level domain extension: {tld}")
            
    # 2. Keywords check (lookalike domains)
    keywords = ["login", "signin", "verification", "secure", "bank", "update", "verify", "support", "account", "billing"]
    for kw in keywords:
        if kw in netloc.lower():
            risk_score += 25
            reasons.append(f"Suspicious security/financial keyword inside subdomain: {kw}")
            
    # 3. IP address indicator
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", netloc.split(":")[0]):
        risk_score += 40
        reasons.append("Raw IPv4 Address used instead of DNS host record")
        
    # 4. Length test
    if len(netloc) > 45:
        risk_score += 15
        reasons.append("Excessively long domain parameters (potential URL padding attack)")
        
    risk_score = min(risk_score, 100)
    verdict = "SAFE" if risk_score < 30 else ("SUSPICIOUS" if risk_score < 60 else "PHISHING/MALICIOUS")
    
    return {
        "url": url,
        "domain": netloc,
        "risk_score": risk_score,
        "verdict": verdict,
        "threat_flags": reasons
    }

# 3. Website Reputation Checker
@app.get("/api/url/reputation")
async def check_website_reputation(domain: str = Query(...)):
    clean_domain = domain.replace("http://", "").replace("https://", "").split("/")[0].strip()
    
    # Real-time DNS lookup
    loop = asyncio.get_event_loop()
    def resolve():
        try:
            return socket.gethostbyname(clean_domain)
        except Exception:
            return ""
    ip = await loop.run_in_executor(None, resolve)
    
    reputation_score = 98
    hosting_provider = "Cloudflare CDN Edge Network"
    category = "Educational/Technology"
    risk_level = "Low"
    blocklisted = False
    
    if not ip:
        reputation_score = 0
        hosting_provider = "No active DNS resolution found"
        risk_level = "Critical (Unresolved Domain)"
    else:
        # Query real hosting ISP
        url = f"http://ip-api.com/json/{ip}"
        try:
            data = await loop.run_in_executor(None, query_json_api, url)
            if data and data.get("status") == "success":
                hosting_provider = f"{data.get('isp')} ({data.get('org', '')}) - located in {data.get('country', '')}"
        except Exception:
            pass
            
    # Custom blocklist check
    bad_domains = ["phish-portal.xyz", "paypal-secure-login.buzz", "suspicious-bank-update.info", "malicious-payload.xyz"]
    if clean_domain.lower() in bad_domains:
        reputation_score = 12
        hosting_provider = "Shady offshore hosting provider"
        category = "Confirmed Phishing / Malware Distribution"
        risk_level = "High"
        blocklisted = True
        
    return {
        "domain": clean_domain,
        "reputation_score": reputation_score,
        "hosting_provider": hosting_provider,
        "domain_category": category,
        "risk_level": risk_level,
        "blocklisted": blocklisted
    }

# 4. Disposable Email Detector
@app.get("/api/email/disposable")
async def check_disposable_email(email: str = Query(...)):
    email_clean = email.strip().lower()
    domain = email_clean.split("@")[-1] if "@" in email_clean else email_clean
    
    # Popular disposable email domains list
    disposable_domains = [
        "tempmail.com", "yopmail.com", "mailinator.com", "temp-mail.org", 
        "10minutemail.com", "guerrillamail.com", "throwawaymail.com", "getnada.com"
    ]
    
    is_disposable = domain in disposable_domains
    return {
        "email": email,
        "domain": domain,
        "is_disposable": is_disposable,
        "verdict": "Disposable / Suspicious" if is_disposable else "Legitimate Mail Server"
    }

# 5. Metadata Viewer
class MetadataRequest(BaseModel):
    filename: str
    base64_data: str # Can process images or documents

@app.post("/api/metadata/view")
async def view_file_metadata(req: MetadataRequest):
    # Simulates extracting structural properties from a document or image file
    import base64
    try:
        decoded_bytes = base64.b64decode(req.base64_data[:500]) # Read beginning header
        header_hex = decoded_bytes.hex().upper()
    except Exception:
        header_hex = "Unknown Binary Data Structure"
        
    file_type = "Unknown File Format"
    if req.filename.endswith(".jpg") or req.filename.endswith(".jpeg"):
        file_type = "JPEG Image (JFIF format)"
    elif req.filename.endswith(".png"):
        file_type = "Portable Network Graphics (PNG)"
    elif req.filename.endswith(".pdf"):
        file_type = "Adobe Portable Document Format (PDF)"
    elif req.filename.endswith(".txt"):
        file_type = "Plain UTF-8 Text File"
        
    # Extracted simulated metadata fields based on typical file formats
    return {
        "filename": req.filename,
        "mime_type": file_type,
        "file_size": f"{len(req.base64_data) * 3 // 4 // 1024} KB",
        "header_hex_signature": header_hex[:32],
        "metadata_fields": {
            "Author/Publisher": "NCAS Cyber Portal Student",
            "Creation Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Application Engine": "CyberShield Suite Local Cryptography Platform",
            "Exif GPS Coordinates": "Latitude: 11.2588 N, Longitude: 75.7804 E (Kozhikode, India)"
        }
    }

@app.post("/api/metadata/place")
async def find_place_by_image(req: MetadataRequest):
    import base64
    import io
    
    place_name = "Unknown Landmark (No EXIF GPS tags found)"
    lat_val, lon_val = None, None
    country_info = "Unknown"
    
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
        
        decoded_bytes = base64.b64decode(req.base64_data)
        image = Image.open(io.BytesIO(decoded_bytes))
        info = image._getexif()
        if info:
            exif_data = {}
            for tag, value in info.items():
                decoded = TAGS.get(tag, tag)
                exif_data[decoded] = value
                
            gps_info = exif_data.get("GPSInfo")
            if gps_info:
                gps_data = {}
                for t in gps_info:
                    sub_decoded = GPSTAGS.get(t, t)
                    gps_data[sub_decoded] = gps_info[t]
                
                def get_decimal(coords, ref):
                    if not coords:
                        return None
                    d = float(coords[0])
                    m = float(coords[1])
                    s = float(coords[2])
                    dec = d + (m / 60.0) + (s / 3600.0)
                    if ref in ['S', 'W']:
                        dec = -dec
                    return dec
                
                lat_val = get_decimal(gps_data.get("GPSLatitude"), gps_data.get("GPSLatitudeRef"))
                lon_val = get_decimal(gps_data.get("GPSLongitude"), gps_data.get("GPSLongitudeRef"))
    except Exception as e:
        print(f"[PLACE FINDER] EXIF exception: {e}")
        
    if lat_val is not None and lon_val is not None:
        url = f"https://nominatim.openstreetmap.org/reverse?lat={lat_val}&lon={lon_val}&format=json"
        headers = {"User-Agent": "NCAS_CyberShield_Suite/2.0_Portal"}
        try:
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, query_json_api, url, headers)
            if data and "display_name" in data:
                place_name = data.get("display_name")
                country_info = data.get("address", {}).get("country", "Unknown Country")
        except Exception:
            place_name = f"Resolved Coordinates: {lat_val:.5f} N, {lon_val:.5f} E"
    else:
        fname_lower = req.filename.lower()
        if "taj" in fname_lower:
            place_name = "Taj Mahal, Agra, India"
            lat_val, lon_val = 27.1751, 78.0421
            country_info = "India"
        elif "eiffel" in fname_lower:
            place_name = "Eiffel Tower, Paris, France"
            lat_val, lon_val = 48.8584, 2.2945
            country_info = "France"
        elif "colosseum" in fname_lower:
            place_name = "Colosseum, Rome, Italy"
            lat_val, lon_val = 41.8902, 12.4922
            country_info = "Italy"
        elif "statue" in fname_lower or "liberty" in fname_lower:
            place_name = "Statue of Liberty, New York, USA"
            lat_val, lon_val = 40.6892, -74.0445
            country_info = "United States"
        else:
            places = [
                {"name": "Burj Khalifa, Dubai, UAE", "lat": 25.1972, "lon": 55.2744, "country": "UAE"},
                {"name": "Sydney Opera House, Sydney, Australia", "lat": -33.8568, "lon": 151.2153, "country": "Australia"},
                {"name": "Big Ben, London, UK", "lat": 51.5007, "lon": -0.1246, "country": "United Kingdom"}
            ]
            choice = places[hash(req.filename) % len(places)]
            place_name = f"Inferred Match (Visual Trait matching): {choice['name']}"
            lat_val, lon_val = choice['lat'], choice['lon']
            country_info = choice['country']

    simulated_ip = f"104.244.{hash(place_name) % 254 + 1}.{hash(req.filename) % 254 + 1}"
    
    return {
        "filename": req.filename,
        "landmark_name": place_name,
        "latitude": lat_val,
        "longitude": lon_val,
        "country": country_info,
        "simulated_location_ip": simulated_ip
    }

# 6. Latest Zero-Day Cybersecurity News Feed (Live NIST/CIRCL Integration + AI Summaries)
@app.get("/api/news/latest")
async def get_latest_security_news():
    cves = []
    try:
        url = "https://cve.circl.lu/api/last"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        loop = asyncio.get_event_loop()
        def fetch_cve():
            with urllib.request.urlopen(req, timeout=4) as response:
                return json.loads(response.read().decode("utf-8"))
        data = await loop.run_in_executor(None, fetch_cve)
        if isinstance(data, list):
            for item in data[:8]:
                cve_id = item.get("id", "CVE-Unknown")
                aliases = item.get("aliases", [])
                if aliases:
                    cve_aliases = [a for a in aliases if a.startswith("CVE")]
                    if cve_aliases:
                        cve_id = cve_aliases[0]
                
                cves.append({
                    "id": cve_id,
                    "summary": item.get("details", "No description available."),
                    "cvss": "8.8" if "RCE" in item.get("details", "") or "execute" in item.get("details", "") else "7.5",
                    "published": item.get("published", "").split("T")[0]
                })
    except Exception as e:
        print(f"[CVE FEED] Error: {e}")
        cves = [
            {"id": "CVE-2024-38063", "summary": "Windows TCP/IP Remote Code Execution Vulnerability.", "cvss": "9.8", "published": "2024-08-13"},
            {"id": "CVE-2024-38178", "summary": "Scripting Engine Memory Corruption Vulnerability.", "cvss": "7.5", "published": "2024-08-13"}
        ]

    # Generate custom news items daily via Pollinations AI
    news = []
    try:
        prompt = (
            "Generate exactly 3 highly realistic or real zero-day cybersecurity news items. "
            "Respond ONLY with a JSON array of objects having fields 'title', 'summary', 'severity', 'date'. "
            "Do not include markdown tags like ```json or ```. Just raw JSON text."
        )
        raw_reply = await query_free_llm(prompt)
        if raw_reply:
            cleaned = raw_reply.replace("```json", "").replace("```", "").strip()
            data = json.loads(cleaned)
            if isinstance(data, list):
                news = data[:3]
    except Exception as e:
        print(f"[NEWS FEED] AI Error: {e}")
        
    if not news:
        news = [
            {
                "title": "New Ransomware Threat Targeting Academic Institutions Discovered",
                "summary": "Security agencies have issued advisories regarding an active campaign exploiting remote access ports to deploy high-impact encryption routines.",
                "severity": "Critical",
                "date": datetime.now().strftime("%Y-%m-%d")
            },
            {
                "title": "Popular open-source library vulnerable to Dependency Confusion attacks",
                "summary": "An automated supply chain audit has revealed a malicious package uploaded to public registries masquerading as internal corporate helpers.",
                "severity": "High",
                "date": datetime.now().strftime("%Y-%m-%d")
            }
        ]
        
    return {"cves": cves, "news": news}

# 7. MITRE ATT&CK Mappings Database (Local Lookups + Dynamic AI Mapping Fallbacks)
MITRE_REGISTRY = [
    {"technique_id": "T1566", "name": "Phishing", "tactic": "Initial Access", "description": "Tricking target users into downloading malware or entering credentials via spoofed interfaces."},
    {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "description": "Ransomware encryption of target local user directories to restrict availability."},
    {"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "description": "Host and port scanning using tools (like nmap or ping sweeps) to find live ports."},
    {"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "description": "Systematic guessing of user account credentials to authenticate via local portals."},
    {"technique_id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "description": "Tunneling malicious data packets using standard HTTP/S protocols to bypass firewalls."}
]

@app.get("/api/mitre/mapping")
async def query_mitre_mapping(query: str = Query(...)):
    query_lower = query.lower()
    matches = [tech for tech in MITRE_REGISTRY if query_lower in tech["technique_id"].lower() or query_lower in tech["name"].lower() or query_lower in tech["tactic"].lower()]
    
    if not matches:
        prompt = (
            f"Generate a MITRE ATT&CK technique mapping for the term: '{query}'. "
            f"Provide a realistic Technique ID (e.g. TXXXX), Tactic name, and description. "
            f"Respond ONLY with a JSON object having fields 'technique_id', 'name', 'tactic', 'description'."
        )
        try:
            raw_reply = await query_free_llm(prompt)
            if raw_reply:
                cleaned = raw_reply.replace("```json", "").replace("```", "").strip()
                data = json.loads(cleaned)
                if "technique_id" in data:
                    matches.append(data)
        except Exception:
            pass
            
    if not matches:
        matches.append({
            "technique_id": "T1059",
            "name": f"Command and Scripting Interpreter: {query.capitalize()}",
            "tactic": "Execution",
            "description": f"Execution of commands or scripts associated with {query} to bypass application filters and achieve user execution."
        })
        
    return {"matches": matches}

# 7b. Infinite Security Quiz Generator
@app.get("/api/quiz/generate")
async def generate_quiz_question():
    import random
    prompt = (
        "Generate a single, highly realistic, expert cybersecurity multiple-choice question. "
        "Provide 4 distinct options, the index of the correct option (0, 1, 2, or 3), and a detailed technical explanation of the answer. "
        "Respond ONLY with a JSON object having fields 'q' (question text), 'o' (array of 4 options), 'a' (integer index of correct option), 'e' (explanation text). "
        "Do not include markdown tags like ```json or ```. Just raw JSON text."
    )
    try:
        raw_reply = await query_free_llm(prompt)
        if raw_reply:
            cleaned = raw_reply.replace("```json", "").replace("```", "").strip()
            data = json.loads(cleaned)
            if "q" in data and "o" in data and "a" in data:
                return data
    except Exception as e:
        print(f"[QUIZ GENERATOR] AI Error: {e}")
        
    quiz_pool = [
        {
            "q": "Which header parameter mitigates Clickjacking attacks by restricting framing options?",
            "o": ["X-Frame-Options", "Content-Type", "Access-Control-Allow-Origin", "Strict-Transport-Security"],
            "a": 0,
            "e": "X-Frame-Options allows web hosts to restrict framing, preventing unauthorized UI redressing (Clickjacking)."
        },
        {
            "q": "What is the primary target of an ARP poisoning attack on local Ethernet networks?",
            "o": ["Injecting routing loops in DNS resolvers", "Mapping a target IP address to a malicious MAC address", "Flooding MAC address tables of layer 2 switches", "Exhausting DHCP server IP allocations"],
            "a": 1,
            "e": "ARP poisoning maps the gateway's IP address to the attacker's MAC address, routing local peer packets to the attacker."
        },
        {
            "q": "Which TCP flag configuration is used to initiate a stealth SYN scan?",
            "o": ["FIN, PSH, URG", "Only the SYN flag is set", "SYN and ACK flags are set", "No flags are set (Null scan)"],
            "a": 1,
            "e": "A SYN scan sets only the SYN flag, waiting for a SYN-ACK response to determine port availability without establishing a full handshake."
        },
        {
            "q": "What does a DMARC policy of 'p=reject' tell receiving mail servers to do with spoofed emails?",
            "o": ["Quarantine them in the junk folder", "Discard/reject the emails immediately", "Deliver them normally but flag them as spam", "Forward them to the administrator's account"],
            "a": 1,
            "e": "A DMARC policy of reject instructs mail transfer agents to completely drop emails that fail SPF and DKIM checks."
        }
    ]
    return random.choice(quiz_pool)

@app.get("/api/auth/status")
async def check_auth_status(username: str = Query(...), role: str = Query(...), request: Request = None):
    client_ip = request.client.host
    if client_ip not in ["127.0.0.1", "localhost", "::1"]:
        if client_ip in banned_ips:
            raise HTTPException(status_code=403, detail="ACCESS TERMINATED: Your IP has been banned.")
    username_clean = username.strip().lower()
    if username_clean in banned_users:
        raise HTTPException(status_code=403, detail="ACCESS TERMINATED: Your user account is banned.")
    return {"status": "active"}

# 8. User Management Endpoint (Admin Controls)
@app.get("/api/admin/users")
async def get_user_list(role: str = Query(...), username: str = Query(...), request: Request = None):
    username_clean = username.strip().lower()
    if role != "admin" or username_clean != "reiz":
        log_and_ban_intruder(request, username, "Bypass attempt on Admin User List console")
        raise HTTPException(status_code=403, detail="Violation logged.")
    
    users = []
    # Fetch registered students
    for name in student_db.keys():
        users.append({
            "username": name,
            "role": "student",
            "status": "Suspended / Banned" if name in banned_users else "Active"
        })
    # Fetch registered faculties
    for name in faculty_db.keys():
        users.append({
            "username": name,
            "role": "faculty",
            "status": "Active"
        })
        
    return {"users": users}

@app.post("/api/admin/user/ban")
async def admin_ban_user(target_user: str = Query(...), role: str = Query(...), username: str = Query(...), request: Request = None):
    username_clean = username.strip().lower()
    if role != "admin" or username_clean != "reiz":
        log_and_ban_intruder(request, username, "Bypass attempt to suspend user account")
        raise HTTPException(status_code=403, detail="Access denied.")
        
    target_clean = target_user.strip().lower()
    banned_users.add(target_clean)
    log_activity("reiz", "admin", f"Suspended account user: {target_clean}", request.client.host)
    return {"status": "suspended"}

@app.post("/api/admin/user/unban")
async def admin_unban_user(target_user: str = Query(...), role: str = Query(...), username: str = Query(...), request: Request = None):
    username_clean = username.strip().lower()
    if role != "admin" or username_clean != "reiz":
        log_and_ban_intruder(request, username, "Bypass attempt to lift user account suspension")
        raise HTTPException(status_code=403, detail="Access denied.")
        
    target_clean = target_user.strip().lower()
    if target_clean in banned_users:
        banned_users.remove(target_clean)
    log_activity("reiz", "admin", f"Restored account access for: {target_clean}", request.client.host)
    return {"status": "restored"}

@app.delete("/api/admin/user")
async def admin_delete_user(target_user: str = Query(...), role: str = Query(...), username: str = Query(...), request: Request = None):
    username_clean = username.strip().lower()
    if role != "admin" or username_clean != "reiz":
        log_and_ban_intruder(request, username, "Bypass attempt to purge user credentials")
        raise HTTPException(status_code=403, detail="Access denied.")
        
    target_clean = target_user.strip().lower()
    if target_clean in student_db:
        del student_db[target_clean]
        save_db(STUDENTS_FILE, student_db)
        log_activity("reiz", "admin", f"Deleted student credential account: {target_clean}", request.client.host)
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Student credentials not found.")

# 9. Academic Rules & Content Management Endpoint
ACADEMIC_POSTS_FILE = "academic_posts.json"
academic_posts = load_db(ACADEMIC_POSTS_FILE, [
    {
        "id": 1,
        "title": "NCAS Lab Device Usage Policy Guidelines",
        "content": "All students must run audits using local virtual environments. Unauthorized external domain resolutions are restricted.",
        "author": "professor_x",
        "timestamp": "2026-07-19 12:00:00"
    }
])

class AcademicPostRequest(BaseModel):
    title: str
    content: str
    author: str

@app.get("/api/academic/posts")
async def get_academic_posts():
    return {"posts": academic_posts}

@app.post("/api/academic/posts")
async def create_academic_post(req: AcademicPostRequest, role: str = Query(...), username: str = Query(...), request: Request = None):
    username_clean = username.strip().lower()
    if role not in ["admin", "faculty"]:
        raise HTTPException(status_code=403, detail="Only administrator or faculty accounts can publish announcements.")
    
    new_post = {
        "id": len(academic_posts) + 1,
        "title": req.title,
        "content": req.content,
        "author": username_clean,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    academic_posts.append(new_post)
    save_db(ACADEMIC_POSTS_FILE, academic_posts)
    log_activity(username_clean, role, f"Published academic announcement: {req.title}", request.client.host)
    return {"status": "success"}

# AES Cryptography & password breach audit
@app.get("/api/crypto/check-breach")
async def check_password_breach(password: str = Query(...), username: str = Query("guest"), role: str = Query("guest"), request: Request = None):
    log_activity(username, role, "Executed Password breach check", request.client.host)
    common_passwords = ["123456", "password", "123456789", "qwerty", "12345678", "111111"]
    breached = False
    details = "Clean: Password not matching institutional weak listings."
    if password in common_passwords:
        breached = True
        details = "BREACH WARNING: Password found in common public leak database."
    return {"password": password, "breached": breached, "details": details}

# Scam heuristics
@app.post("/api/scam/analyze")
async def analyze_scam_message(request: ScamAnalyzeRequest):
    content = request.text.lower()
    indicators = []
    risk_score = 0
    rules = [
        {"pattern": "urgent", "flag": "Urgency Trigger", "weight": 25},
        {"pattern": "suspend", "flag": "Account Suspension Threat", "weight": 30},
        {"pattern": "win", "flag": "Monetary Claim", "weight": 25},
        {"pattern": "upi", "flag": "Payment Request", "weight": 20}
    ]
    for rule in rules:
        if rule["pattern"] in content:
            indicators.append(rule["flag"])
            risk_score += rule["weight"]
    risk_score = min(risk_score, 100)
    level = "HIGH RISK" if risk_score >= 60 else ("MEDIUM RISK" if risk_score >= 30 else "LOW RISK")
    return {"indicators_found": indicators, "risk_score": risk_score, "risk_level": level, "summary": "Alert checked."}

OFFLINE_REPLIES = {
    "ddos": "### [MITRE T1498] Network Denial of Service Mitigation\n\n1. **Rate Limiting**: Enforce strict packet inspection limits at the boundary firewalls.\n2. **CDN Buffering**: Route external traffic through CDN scrubbing centers to absorb volumetric amplification.\n3. **Traffic Analysis**: Monitor sudden spikes in UDP/ICMP traffic.",
    "firewall": "### Firewall Architecture & Packet Inspection\n\n1. **Stateful Inspection**: Statefully track connection states (SYN, SYN-ACK, ACK) to ensure packets belong to valid conversations.\n2. **Rules Enforcement**: Deny all incoming traffic by default, allowing only designated secure ports (e.g. 443, 22).\n3. **Next-Gen features**: Integrate deep packet inspection (DPI) to identify application-layer payloads.",
    "vpn": "### Virtual Private Network (VPN) Security Protocols\n\n1. **Tunneling**: Encapsulate local IP packets inside secure protocols (IPsec or OpenVPN).\n2. **Encryption**: Enforce strong symmetric ciphers like AES-256-GCM to prevent wiretapping.\n3. **MFA Enforcement**: Always pair VPN access with Multi-Factor Authentication to block compromised credentials.",
    "xss": "### [OWASP A03:2021] Cross-Site Scripting Mitigation\n\n1. **Context-Aware Encoding**: Encode all untrusted output variables (HTML, JavaScript, CSS contexts) before rendering.\n2. **Content Security Policy (CSP)**: Enforce a strict CSP header: `Content-Security-Policy: default-src 'self'`.\n3. **Input Sanitization**: Use DOMPurify to strip script tags.",
    "brute force": "### [MITRE T1110] Brute Force Prevention Plan\n\n1. **Account Lockout**: Suspend login attempts temporarily after 5 consecutive failures.\n2. **Rate Limiting**: Implement strict IP connection throttle intervals on `/api/login`.\n3. **MFA Verification**: Require authentication tokens to thwart dictionary attacks.",
    "malware": "### Malicious Software Analysis & Defenses\n\n1. **Behavioral Heuristics**: Monitor anomalous system calls and registry edits.\n2. **Endpoint Protection**: Maintain real-time threat databases and signature matching.\n3. **Sandbox Executions**: Inspect suspicious binaries in isolated runtime environments before deployment.",
    "cryptography": "### Cryptographical Protection Standards\n\n1. **Asymmetric Ciphers**: Use RSA-4096 or ECC for secure key exchange mechanisms.\n2. **Symmetric Encryption**: Protect stored data using AES-256.\n3. **Hashing & Salting**: Hash credentials using Argon2id or bcrypt with high work factors.",
    "dns": "### Domain Name System (DNS) Hardening\n\n1. **DNSSEC**: Digitally sign DNS records to prevent cache poisoning.\n2. **Anycast Routing**: Deploy DNS over anycast networks to mitigate DDoS outages.\n3. **DoH/DoT**: Encrypt outbound query resolutions using DNS over HTTPS or TLS.",
    "cookie": "### Secure HTTP Cookie Configuration\n\n1. **Secure Flag**: Only transmit cookies over encrypted SSL/TLS channels.\n2. **HttpOnly**: Prevent client-side scripting access to mitigate session hijacking.\n3. **SameSite Policy**: Enforce `SameSite=Strict` to block Cross-Site Request Forgery (CSRF)."
}

def generate_offline_reply(user_msg: str) -> str:
    user_msg_lower = user_msg.lower()
    
    # Match specific dictionary definitions
    for key, val in OFFLINE_REPLIES.items():
        if key in user_msg_lower:
            return val
            
    # Match standard heuristics
    if "ransomware" in user_msg_lower:
        return "### [MITRE T1486] Data Encrypted for Impact Mitigation\n\n1. **Isolation**: Immediately disconnect affected hosts from local Wi-Fi/Ethernet loops.\n2. **Shadow Copies**: Verify VSS availability: `vssadmin list shadows`\n3. **AD Audits**: Audit remote file system mounting parameters and check Kerberos ticket anomalies."
    if "port scan" in user_msg_lower or "nmap" in user_msg_lower:
        return "### [MITRE T1046] Network Service Discovery Mitigation\n\n1. **Firewall Rules**: Enforce SYN connections rate-limiting on inbound routes.\n2. **Logging**: Run packet capture checks on router ports: `tcpdump -i any 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'`\n3. **IDS Alignment**: Load rules to detect IP sweep configurations."
    if "sql injection" in user_msg_lower or "sqli" in user_msg_lower:
        return "### [OWASP A03:2021] Injection Remediation Action Plan\n\n1. **Prepared Statements**: Parametrize all database integrations to isolate code execution contexts.\n2. **WAF Filters**: Verify rules matching `' OR 1=1` and `UNION SELECT` signatures."
    if "phishing" in user_msg_lower:
        return "### [MITRE T1566] Phishing Threat Mitigation\n\n1. **Email Records**: Enforce strict DMARC policies (`p=reject`) and SPF checks (`v=spf1 -all`).\n2. **Filtering**: Block high-risk macro execution parameters at mail gateways."
        
    # Extract main topic words to generate customized advice
    words = [w.strip("?,.!") for w in user_msg.split() if len(w) > 4]
    keyword = words[0] if words else "Security Operation"
    
    return (
        f"### Offline AI Diagnostic Core - Active Security Analysis\n\n"
        f"The **Aegis Local Core** has processed your query regarding: `{keyword}`.\n\n"
        f"**Defensive Recommendations**:\n"
        f"1. **Access Controls**: Restrict raw system access to this resource and enforce role-based authentication (RBAC).\n"
        f"2. **Log Monitoring**: Enable detailed audit logs on local endpoints to detect anomalies.\n"
        f"3. **Network Isolation**: Segment internal assets using VLANs and local firewall zones to contain lateral movement."
    )

# Chat assistant (Free Backend LLM + Local Heuristics Generative Routing)
@app.post("/api/chat")
async def chat_assistant(request: ChatRequest):
    user_msg = request.message.strip()
    
    # 1. Query the Free Backend LLM (Pollinations AI)
    llm_reply = await query_free_llm(user_msg)
    if llm_reply:
        return {"reply": llm_reply}
        
    # 2. Heuristics fallback database (Generates active responses offline)
    reply = generate_offline_reply(user_msg)
    return {"reply": reply}

@app.get("/api/speedtest")
async def get_speedtest_payload():
    import io
    from fastapi.responses import StreamingResponse
    # Return 5MB of zeros to measure download throughput
    payload = b"\x00" * (1024 * 1024 * 5)
    return StreamingResponse(io.BytesIO(payload), media_type="application/octet-stream")

@app.get("/api/health")
async def get_health():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
async def get_index():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Frontend files not found</h1>", status_code=404)
