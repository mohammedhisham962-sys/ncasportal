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
    allow_credentials=True,
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

# Ban lists & Intruder logs database
banned_ips = set()
banned_users = set()
security_alerts = []
user_activities = []  # Live activity tracking database

def log_activity(username: str, role: str, action: str, ip: str):
    user_activities.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "username": username,
        "role": role,
        "action": action,
        "ip": ip
    })

# Middleware to intercept and reject banned IPs
@app.middleware("http")
async def check_ban_status(request: Request, call_next):
    client_ip = request.client.host
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
    client_ip = request.client.host
    if username_clean in ["admin", "reiz"]:
        log_and_ban_intruder(request, req.username, "Privilege escalation attempt during signup")
        raise HTTPException(status_code=403, detail="Violation logged.")
    if username_clean in student_db or username_clean in faculty_db:
        raise HTTPException(status_code=400, detail="Username already registered.")
    student_db[username_clean] = req.password
    save_db(STUDENTS_FILE, student_db) # Persist on signup
    log_activity(username_clean, "student", "Account registration completed", client_ip)
    return {"status": "success"}

@app.post("/api/login")
async def login(req: LoginRequest, request: Request):
    username_clean = req.username.strip().lower()
    password = req.password
    client_ip = request.client.host
    
    if username_clean == admin_credentials["username"]:
        if password == admin_credentials["password"]:
            log_activity("reiz", "admin", "Admin portal login successful", client_ip)
            return {"status": "authenticated", "role": "admin", "username": "reiz"}
            
        log_activity("reiz", "admin", "Admin login failed: Incorrect password", client_ip)
        raise HTTPException(status_code=401, detail="Invalid admin credentials.")
        
    if username_clean in faculty_db:
        if faculty_db[username_clean] == password:
            log_activity(username_clean, "faculty", "Faculty portal login successful", client_ip)
            return {"status": "authenticated", "role": "faculty", "username": username_clean}
            
        log_activity(username_clean, "faculty", "Faculty login failed: Incorrect password", client_ip)
        raise HTTPException(status_code=401, detail="Invalid faculty credentials.")
        
    if username_clean in student_db:
        if student_db[username_clean] == password:
            log_activity(username_clean, "student", "Student portal login successful", client_ip)
            return {"status": "authenticated", "role": "student", "username": username_clean}
            
        log_activity(username_clean, "student", "Student login failed: Incorrect password", client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials.")
        
    log_activity(username_clean, "unknown", "Login failed: User not found", client_ip)
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
                f"Incident ID: {req.id}\n"
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
    
    faculty_limit = load_db("faculty_limit.json", 5)
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
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Dev.to": f"https://dev.to/{username}",
        "Medium": f"https://medium.com/@{username}",
        "GitLab": f"https://gitlab.com/{username}"
    }
    results = []
    async def check_profile(name: str, url: str):
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            loop = asyncio.get_event_loop()
            def fetch_status():
                with urllib.request.urlopen(req, timeout=3) as resp: return resp.getcode()
            code = await loop.run_in_executor(None, fetch_status)
            if code == 200: results.append({"platform": name, "url": url, "status": "Available"})
        except Exception: pass
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

# Threat CVE
@app.get("/api/threat/cve")
async def query_cve_db(query: str = Query(...)):
    cve_database = [
        {"id": "CVE-2021-44228", "title": "Log4Shell", "severity": "Critical (10.0)", "description": "Apache Log4j2 remote code execution vulnerability."},
        {"id": "CVE-2023-38831", "title": "WinRAR RCE", "severity": "High (7.8)", "description": "WinRAR ZIP file processing remote execution vulnerability."},
        {"id": "CVE-2024-3094", "title": "XZ Utils Backdoor", "severity": "Critical (10.0)", "description": "Malicious code injection in XZ Utils payload delivery stream."}
    ]
    matches = [cve for cve in cve_database if query.lower() in cve["id"].lower() or query.lower() in cve["title"].lower()]
    return {"query": query, "matches": matches}

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

# Chat assistant (Enriched Technical Responses & Wide Knowledge Support)
@app.post("/api/chat")
async def chat_assistant(request: ChatRequest):
    user_msg = request.message.lower().strip()
    
    # Advanced pattern match rules for broad cybersecurity and internet queries
    if "ransomware" in user_msg or "malware" in user_msg or "virus" in user_msg:
        reply = "### [MITRE T1486] Data Encrypted for Impact Mitigation\n\n1. **Isolation**: Immediately disconnect affected hosts from local Wi-Fi/Ethernet loops to stop lateral spread.\n2. **Shadow Copies**: Verify VSS availability: `vssadmin list shadows`\n3. **Backups**: Retrieve immutable offsite backup snapshots.\n4. **Audit**: Run malware scan via Windows Defender: `MpCmdRun.exe -SignatureUpdate`"
    elif "port scan" in user_msg or "nmap" in user_msg or "scanning" in user_msg:
        reply = "### [MITRE T1046] Network Service Discovery Mitigation\n\n1. **Firewall Rules**: Enforce SYN connections rate-limiting on inbound routes.\n2. **Logging**: Run packet capture checks on router ports: `tcpdump -i any 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'`\n3. **IDS Alignment**: Configure Snort/Suricata rules to identify and drop rapid IP sweeps."
    elif "sql injection" in user_msg or "sqli" in user_msg or "database hack" in user_msg:
        reply = "### [OWASP A03:2021] Injection Remediation Action Plan\n\n1. **Prepared Statements**: Parametrize all database integrations to isolate code execution contexts.\n2. **WAF Filters**: Verify rules matching `' OR 1=1` and `UNION SELECT` signatures.\n3. **Sanitization**: Strictly filter out query characters like single quotes, semi-colons, and dashes from input parameters."
    elif "phishing" in user_msg or "fake email" in user_msg or "scam link" in user_msg:
        reply = "### [MITRE T1566] Phishing Threat Mitigation\n\n1. **Email Records**: Enforce strict DMARC policies (`p=reject`) and SPF checks (`v=spf1 -all`).\n2. **Header Audits**: Look at the sender address headers to spot character substitutions (typosquatting).\n3. **Training**: Never click links requesting sudden credentials confirmation or prompt bank transfers."
    elif "mfa" in user_msg or "authentication" in user_msg or "login secure" in user_msg:
        reply = "### [MITRE T1556] Authenticator Protections\n\n1. **Hardware Keys**: Enforce FIDO2 / WebAuthn standard security keys over SMS validation.\n2. **Conditional Access**: Block credential validation from unverified browser agents.\n3. **Session Expiring**: Reduce token lifetime to minimize hijack exposures."
    elif "wi-fi" in user_msg or "router" in user_msg or "wireless" in user_msg:
        reply = "### Wireless Network Security Standards\n\n1. **Encryption**: Always configure WPA3-SAE. Avoid outdated WEP/WPA protocols.\n2. **AP Isolation**: Enable AP Isolation on routers to prevent peers from sniffing packet streams.\n3. **Credentials**: Change the default admin interface password (e.g. admin/admin) to prevent takeover."
    elif "ip address" in user_msg or "subnet" in user_msg:
        reply = "### IP Address Protocol Overview\n\nAn IP (Internet Protocol) address is a unique identifier assigned to devices on a network. IPv4 uses 32-bit values (e.g. `192.168.1.1`), while IPv6 uses 128-bit hexadecimal strings (e.g. `2001:0db8::`). Keep public IPs masked using a VPN to prevent location tracking."
    elif "cookie" in user_msg or "browser hijack" in user_msg:
        reply = "### Browser Cookie Protection Guidelines\n\nCookies store user session parameters. Mitigate hijacks by setting HTTP headers: `Secure` (forces HTTPS transmission), `HttpOnly` (blocks access via JavaScript/XSS), and `SameSite=Strict` (prevents CSRF attacks)."
    elif "dns" in user_msg or "domain name" in user_msg:
        reply = "### Domain Name System (DNS) Security\n\nDNS translates domain names (e.g. google.com) to IP addresses. Ensure you configure DNSSEC to authenticate lookups, or use Encrypted DNS (DNS over HTTPS/TLS) to prevent local network ISP tracking."
    elif "hello" in user_msg or "hi" in user_msg or "who are you" in user_msg:
        reply = "### NCAS CyberShield Assistant\n\nI am your advanced cybersecurity intelligence agent. You can ask me any questions about network defense, email phishing, Wi-Fi security, malware, or database hardening!"
    else:
        reply = f"### Defensive Intelligence Report\n\nRegarding your query about **'{user_msg}'**:\n\nEnsure that you evaluate system access controls, inspect network logs for anomalies, enforce transport layer security (TLS 1.3), and consult security guidelines such as OWASP Top 10 or MITRE ATT&CK."
        
    return {"reply": reply}

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
