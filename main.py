"""
Telegram Mini App Backend - User Reputation Checker
"""

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
import sqlite3
import re
from datetime import datetime
from collections import defaultdict
import time
import requests
import os

app = FastAPI()

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://cherrygram.xyz",
        "https://cherrygram.xyz/",
        "https://cherrygram-frontend.vercel.app"
    ],  # укажи сюда все домены фронта
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===== НАСТРОЙКИ =====
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
TELEGRAM_ADMIN_CHAT_ID = os.getenv("TELEGRAM_ADMIN_CHAT_ID", "YOUR_CHAT_ID_HERE")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:8080")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting
rate_limit_storage = defaultdict(list)
RATE_LIMIT = 10
RATE_WINDOW = 60

def check_rate_limit(ip: str) -> bool:
    now = time.time()
    rate_limit_storage[ip] = [req_time for req_time in rate_limit_storage[ip] 
                              if now - req_time < RATE_WINDOW]
    if len(rate_limit_storage[ip]) >= RATE_LIMIT:
        return False
    rate_limit_storage[ip].append(now)
    return True

# Database
def init_db():
    conn = sqlite3.connect('reputation.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS scam_list
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  reason TEXT,
                  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS whitelist
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  profile_image TEXT,
                  profile_description TEXT,
                  profile_badge TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS applications
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  description TEXT NOT NULL,
                  proof TEXT,
                  status TEXT DEFAULT 'pending',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS scam_reports
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  reporter_username TEXT,
                  scammer_username TEXT NOT NULL,
                  description TEXT NOT NULL,
                  proof_links TEXT,
                  status TEXT DEFAULT 'pending',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    try:
        c.execute("INSERT INTO scam_list (username, reason) VALUES (?, ?)",
                 ("scammer123", "Подтверждённое мошенничество"))
        c.execute("""INSERT INTO whitelist 
                     (username, profile_image, profile_description, profile_badge) 
                     VALUES (?, ?, ?, ?)""",
                  ("trusteduser", 
                   "https://via.placeholder.com/80?text=VIP",
                   "Официальный гарант сделок. Проверен администрацией. Более 1000 успешных сделок.",
                   "⭐ Премиум гарант"))
    except sqlite3.IntegrityError:
        pass
    
    conn.commit()
    conn.close()

init_db()

# Telegram functions
def send_telegram_message(text: str, parse_mode: str = "HTML"):
    if TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("⚠️ Telegram bot not configured. Message:", text)
        return False
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_ADMIN_CHAT_ID, "text": text, "parse_mode": parse_mode}
    
    try:
        response = requests.post(url, json=data, timeout=10)
        return response.json().get("ok", False)
    except Exception as e:
        print(f"Error: {e}")
        return False

def send_telegram_photo(photo_data: bytes, caption: str):
    if TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        return False
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendPhoto"
    files = {"photo": photo_data}
    data = {"chat_id": TELEGRAM_ADMIN_CHAT_ID, "caption": caption, "parse_mode": "HTML"}
    
    try:
        response = requests.post(url, data=data, files=files, timeout=30)
        return response.json().get("ok", False)
    except Exception as e:
        return False

# Models
class CheckRequest(BaseModel):
    username: str
    
    @validator('username')
    def validate_username(cls, v):
        v = v.strip().lstrip('@')
        if not re.match(r'^[a-zA-Z0-9_]{5,32}$', v):
            raise ValueError('Неверный формат username')
        return v.lower()

class ApplicationRequest(BaseModel):
    username: str
    description: str
    proof: str = ""
    
    @validator('username')
    def validate_username(cls, v):
        v = v.strip().lstrip('@')
        if not re.match(r'^[a-zA-Z0-9_]{5,32}$', v):
            raise ValueError('Неверный формат username')
        return v.lower()
    
    @validator('description')
    def validate_description(cls, v):
        if len(v.strip()) < 10:
            raise ValueError('Описание слишком короткое (мин. 10 символов)')
        if len(v) > 500:
            raise ValueError('Описание слишком длинное (макс. 500 символов)')
        return v.strip()

class ScamReportRequest(BaseModel):
    reporter_username: str = ""
    scammer_username: str
    description: str
    proof_links: str = ""
    
    @validator('scammer_username')
    def validate_scammer_username(cls, v):
        v = v.strip().lstrip('@')
        if not re.match(r'^[a-zA-Z0-9_]{5,32}$', v):
            raise ValueError('Неверный формат username')
        return v.lower()
    
    @validator('description')
    def validate_description(cls, v):
        if len(v.strip()) < 20:
            raise ValueError('Описание слишком короткое (мин. 20 символов)')
        if len(v) > 1000:
            raise ValueError('Описание слишком длинное (макс. 1000 символов)')
        return v.strip()

# Endpoints
@app.post("/check")
async def check_reputation(data: CheckRequest, request: Request):
    client_ip = request.client.host
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Слишком много запросов")
    
    username = data.username
    conn = sqlite3.connect('reputation.db')
    c = conn.cursor()
    
    c.execute("SELECT reason, added_at FROM scam_list WHERE username = ?", (username,))
    scam_result = c.fetchone()
    
    if scam_result:
        conn.close()
        return {"status": "scam", "username": username, "reason": scam_result[0], "date": scam_result[1]}
    
    c.execute("""SELECT verified_at, profile_image, profile_description, profile_badge 
                 FROM whitelist WHERE username = ?""", (username,))
    trusted_result = c.fetchone()
    conn.close()
    
    if trusted_result:
        return {
            "status": "trusted",
            "username": username,
            "verified_at": trusted_result[0],
            "profile_image": trusted_result[1],
            "profile_description": trusted_result[2],
            "profile_badge": trusted_result[3]
        }
    
    return {"status": "unknown", "username": username, "message": "Пользователь не найден в базе"}

@app.post("/apply")
async def submit_application(data: ApplicationRequest, request: Request):
    client_ip = request.client.host
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Слишком много запросов")
    
    conn = sqlite3.connect('reputation.db')
    c = conn.cursor()
    
    try:
        c.execute("""INSERT INTO applications (username, description, proof, status)
                     VALUES (?, ?, ?, 'pending')""",
                  (data.username, data.description, data.proof))
        conn.commit()
        app_id = c.lastrowid
        conn.close()
        
        message = f"""
🆕 <b>НОВАЯ ЗАЯВКА НА ВЕРИФИКАЦИЮ</b>

👤 Username: @{data.username}
📝 Описание: {data.description}
🔗 Доказательства: {data.proof if data.proof else 'Не предоставлены'}

ID заявки: #{app_id}
⏰ {datetime.now().strftime('%d.%m.%Y %H:%M')}
"""
        send_telegram_message(message)
        
        return {"success": True, "message": "Заявка отправлена на рассмотрение", "application_id": app_id}
    except sqlite3.Error:
        conn.close()
        raise HTTPException(status_code=500, detail="Ошибка базы данных")

@app.post("/report")
async def report_scam(data: ScamReportRequest, request: Request):
    client_ip = request.client.host
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Слишком много запросов")
    
    conn = sqlite3.connect('reputation.db')
    c = conn.cursor()
    
    try:
        c.execute("""INSERT INTO scam_reports 
                     (reporter_username, scammer_username, description, proof_links, status)
                     VALUES (?, ?, ?, ?, 'pending')""",
                  (data.reporter_username, data.scammer_username, data.description, data.proof_links))
        conn.commit()
        report_id = c.lastrowid
        conn.close()
        
        message = f"""
🚨 <b>НОВАЯ ЖАЛОБА НА МОШЕННИКА!</b>

⚠️ Мошенник: @{data.scammer_username}
👤 Отправитель: {f'@{data.reporter_username}' if data.reporter_username else 'Аноним'}

📄 <b>Описание:</b>
{data.description}

🔗 <b>Доказательства:</b>
{data.proof_links if data.proof_links else 'Не предоставлены'}

ID жалобы: #{report_id}
⏰ {datetime.now().strftime('%d.%m.%Y %H:%M')}
"""
        send_telegram_message(message)
        
        return {"success": True, "message": "Жалоба отправлена на рассмотрение", "report_id": report_id}
    except sqlite3.Error:
        conn.close()
        raise HTTPException(status_code=500, detail="Ошибка базы данных")

@app.post("/upload-screenshot")
async def upload_screenshot(file: UploadFile = File(...), report_id: int = Form(...), caption: str = Form("")):
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Только изображения")
    
    contents = await file.read()
    if len(contents) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Файл слишком большой")
    
    photo_caption = f"📎 <b>Скриншот к жалобе #{report_id}</b>\n\n{caption if caption else 'Без описания'}"
    success = send_telegram_photo(contents, photo_caption)
    
    if success:
        return {"success": True, "message": "Скриншот отправлен"}
    else:
        raise HTTPException(status_code=500, detail="Ошибка отправки")

@app.get("/")
async def root():
    return {"status": "ok", "service": "Reputation Checker API"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
