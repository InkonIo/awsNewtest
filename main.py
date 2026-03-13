from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional
from contextlib import asynccontextmanager
import asyncpg, os, secrets, string
from datetime import datetime, timedelta
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

pool = None

# ── Rate limiting (in-memory) ────────────────────────────────────────────────
login_attempts: dict = defaultdict(list)  # ip -> [timestamps]
RATE_LIMIT = 5       # max attempts
RATE_WINDOW = 300    # seconds (5 min)

def check_rate_limit(ip: str):
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=RATE_WINDOW)
    attempts = [t for t in login_attempts[ip] if t > cutoff]
    login_attempts[ip] = attempts
    if len(attempts) >= RATE_LIMIT:
        wait = int((attempts[0] - cutoff).total_seconds())
        raise HTTPException(status_code=429, detail=f"Слишком много попыток. Подождите {wait} сек.")
    login_attempts[ip].append(now)

def get_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else request.client.host

# ── DB Setup ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    pool = await asyncpg.create_pool(DATABASE_URL)
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id SERIAL PRIMARY KEY,
                key VARCHAR(32) UNIQUE NOT NULL,
                owner_name VARCHAR(255),
                created_at TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP,
                activated_at TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                session_token VARCHAR(64),
                session_started_at TIMESTAMP,
                device_fingerprint VARCHAR(255),
                days INTEGER DEFAULT 30,
                last_seen TIMESTAMP,
                total_time_seconds INTEGER DEFAULT 0,
                streak_days INTEGER DEFAULT 0,
                last_streak_date DATE
            )
        """)
        # Login logs
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (
                id SERIAL PRIMARY KEY,
                key VARCHAR(32),
                ip VARCHAR(64),
                fingerprint VARCHAR(255),
                status VARCHAR(32),
                detail TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        # Question stats (which questions answered wrong most)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS question_stats (
                id SERIAL PRIMARY KEY,
                question_id INTEGER,
                key VARCHAR(32),
                correct BOOLEAN,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        # Bookmarks
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS bookmarks (
                id SERIAL PRIMARY KEY,
                key VARCHAR(32),
                question_id INTEGER,
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(key, question_id)
            )
        """)
        # Leaderboard scores
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS scores (
                id SERIAL PRIMARY KEY,
                key VARCHAR(32) UNIQUE,
                owner_name VARCHAR(255),
                total_correct INTEGER DEFAULT 0,
                total_answered INTEGER DEFAULT 0,
                streak_days INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)
    yield
    await pool.close()

app = FastAPI(lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ── Models ───────────────────────────────────────────────────────────────────
class KeyCreate(BaseModel):
    owner_name: str
    days: int = 30

class KeyLogin(BaseModel):
    key: str
    fingerprint: Optional[str] = None

class AdminLogin(BaseModel):
    password: str

class AnswerLog(BaseModel):
    question_id: int
    correct: bool

class BookmarkToggle(BaseModel):
    question_id: int

class PingTime(BaseModel):
    seconds: int  # time spent in this session chunk

# ── Pages ─────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/quiz", response_class=HTMLResponse)
async def quiz(request: Request):
    return templates.TemplateResponse("quiz.html", {"request": request})

@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})

# ── Auth API ──────────────────────────────────────────────────────────────────
@app.post("/api/login")
async def login(data: KeyLogin, request: Request):
    ip = get_ip(request)
    check_rate_limit(ip)

    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM keys WHERE key = $1", data.key.strip().upper())

        async def log(status, detail=""):
            await conn.execute("""
                INSERT INTO login_logs (key, ip, fingerprint, status, detail)
                VALUES ($1, $2, $3, $4, $5)
            """, data.key.strip().upper(), ip, data.fingerprint, status, detail)

        if not row:
            await log("fail", "Неверный ключ")
            raise HTTPException(status_code=401, detail="Неверный ключ")

        if not row["is_active"]:
            await log("blocked", "Ключ деактивирован")
            raise HTTPException(status_code=403, detail="Ключ деактивирован")

        now = datetime.utcnow()
        if row["expires_at"] and now > row["expires_at"]:
            await log("expired", "Срок истёк")
            raise HTTPException(status_code=403, detail="Срок действия ключа истёк")

        session_token = secrets.token_hex(32)

        if not row["activated_at"]:
            expires_at = now + timedelta(days=int(row["days"] or 30))
            await conn.execute("""
                UPDATE keys SET activated_at=$1, expires_at=$2, session_token=$3,
                    session_started_at=$4, device_fingerprint=$5, last_seen=$4
                WHERE key=$6
            """, now, expires_at, session_token, now, data.fingerprint, data.key.strip().upper())
        else:
            # Update streak
            today = now.date()
            last_date = row["last_streak_date"]
            streak = row["streak_days"] or 0
            if last_date is None or (today - last_date).days > 1:
                streak = 1
            elif last_date != today:
                streak += 1
            await conn.execute("""
                UPDATE keys SET session_token=$1, session_started_at=$2,
                    device_fingerprint=$3, last_seen=$2,
                    streak_days=$4, last_streak_date=$5
                WHERE key=$6
            """, session_token, now, data.fingerprint, streak, today, data.key.strip().upper())

        await log("success")

        # Upsert leaderboard entry
        key_upper = data.key.strip().upper()
        await conn.execute("""
            INSERT INTO scores (key, owner_name) VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET owner_name = $2
        """, key_upper, row["owner_name"])

        updated = await conn.fetchrow("SELECT * FROM keys WHERE key = $1", key_upper)
        return {
            "success": True,
            "session_token": session_token,
            "owner_name": updated["owner_name"],
            "expires_at": updated["expires_at"].isoformat() if updated["expires_at"] else None,
            "key": key_upper,
            "streak_days": updated["streak_days"] or 0
        }

@app.post("/api/verify")
async def verify_session(request: Request):
    body = await request.json()
    token = body.get("session_token")
    key = body.get("key")
    if not token or not key:
        raise HTTPException(status_code=401, detail="Нет токена")
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM keys WHERE key=$1 AND session_token=$2", key, token
        )
        if not row:
            raise HTTPException(status_code=401, detail="Сессия устарела")
        if not row["is_active"]:
            raise HTTPException(status_code=403, detail="Ключ деактивирован")
        now = datetime.utcnow()
        if row["expires_at"] and now > row["expires_at"]:
            raise HTTPException(status_code=403, detail="Срок истёк")
        await conn.execute("UPDATE keys SET last_seen=$1 WHERE key=$2", now, key)
        return {
            "valid": True,
            "owner_name": row["owner_name"],
            "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
            "streak_days": row["streak_days"] or 0
        }

# ── Stats & Gamification API ──────────────────────────────────────────────────
@app.post("/api/answer")
async def log_answer(data: AnswerLog, request: Request):
    """Called from frontend after each answer"""
    body = await request.json()
    key = body.get("key", data.question_id)  # re-read from body
    # Actually read full body
    key = body.get("key")
    if not key:
        raise HTTPException(status_code=401, detail="Нет ключа")
    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO question_stats (question_id, key, correct)
            VALUES ($1, $2, $3)
        """, data.question_id, key, data.correct)
        # Update leaderboard
        if data.correct:
            await conn.execute("""
                INSERT INTO scores (key, total_correct, total_answered, updated_at)
                VALUES ($1, 1, 1, NOW())
                ON CONFLICT (key) DO UPDATE SET
                    total_correct = scores.total_correct + 1,
                    total_answered = scores.total_answered + 1,
                    updated_at = NOW()
            """, key)
        else:
            await conn.execute("""
                INSERT INTO scores (key, total_correct, total_answered, updated_at)
                VALUES ($1, 0, 1, NOW())
                ON CONFLICT (key) DO UPDATE SET
                    total_answered = scores.total_answered + 1,
                    updated_at = NOW()
            """, key)
    return {"ok": True}

@app.post("/api/ping")
async def ping_time(request: Request):
    """Frontend pings every 30s to track time on site"""
    body = await request.json()
    key = body.get("key")
    seconds = int(body.get("seconds", 30))
    if not key:
        return {"ok": False}
    async with pool.acquire() as conn:
        await conn.execute("""
            UPDATE keys SET total_time_seconds = COALESCE(total_time_seconds,0) + $1,
            last_seen = NOW() WHERE key = $2
        """, seconds, key)
    return {"ok": True}

@app.get("/api/leaderboard")
async def leaderboard():
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT s.owner_name,
                   s.total_correct,
                   s.total_answered,
                   CASE WHEN s.total_answered > 0
                        THEN ROUND(s.total_correct::numeric / s.total_answered * 100)
                        ELSE 0 END as accuracy,
                   k.streak_days
            FROM scores s
            JOIN keys k ON k.key = s.key
            WHERE k.is_active = TRUE
              AND (k.expires_at IS NULL OR k.expires_at > NOW())
            ORDER BY s.total_correct DESC
            LIMIT 20
        """)
        return [dict(r) for r in rows]

@app.get("/api/bookmarks/{key}")
async def get_bookmarks(key: str, request: Request):
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT question_id FROM bookmarks WHERE key=$1", key)
        return [r["question_id"] for r in rows]

@app.post("/api/bookmarks")
async def toggle_bookmark(request: Request):
    body = await request.json()
    key = body.get("key")
    qid = body.get("question_id")
    if not key or qid is None:
        raise HTTPException(status_code=400, detail="Нет данных")
    async with pool.acquire() as conn:
        existing = await conn.fetchrow(
            "SELECT id FROM bookmarks WHERE key=$1 AND question_id=$2", key, qid
        )
        if existing:
            await conn.execute("DELETE FROM bookmarks WHERE key=$1 AND question_id=$2", key, qid)
            return {"bookmarked": False}
        else:
            await conn.execute("INSERT INTO bookmarks (key, question_id) VALUES ($1,$2)", key, qid)
            return {"bookmarked": True}

# ── Admin API ─────────────────────────────────────────────────────────────────
@app.post("/api/admin/login")
async def admin_login(data: AdminLogin):
    if data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Неверный пароль")
    return {"success": True, "admin_token": secrets.token_hex(32)}

def check_admin(request: Request):
    if not request.headers.get("X-Admin-Token"):
        raise HTTPException(status_code=401, detail="Нет доступа")

@app.get("/api/admin/keys")
async def list_keys(request: Request):
    check_admin(request)
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT k.*,
                   COALESCE(k.total_time_seconds, 0) as time_sec,
                   (SELECT COUNT(*) FROM question_stats qs WHERE qs.key=k.key AND qs.correct=false) as wrong_count
            FROM keys k
            ORDER BY k.created_at DESC
        """)
        result = []
        for r in rows:
            d = dict(r)
            d['total_time_formatted'] = f"{d['time_sec']//3600}ч {(d['time_sec']%3600)//60}м"
            result.append(d)
        return result

@app.get("/api/admin/stats")
async def admin_stats(request: Request):
    check_admin(request)
    async with pool.acquire() as conn:
        # Top wrong questions
        top_wrong = await conn.fetch("""
            SELECT question_id,
                   COUNT(*) FILTER (WHERE correct=false) as wrong,
                   COUNT(*) as total
            FROM question_stats
            GROUP BY question_id
            ORDER BY wrong DESC
            LIMIT 10
        """)
        # Recent logins
        recent_logs = await conn.fetch("""
            SELECT * FROM login_logs
            ORDER BY created_at DESC LIMIT 20
        """)
        # Summary
        summary = await conn.fetchrow("""
            SELECT
                COUNT(*) as total_keys,
                COUNT(*) FILTER (WHERE is_active=true) as active_keys,
                COUNT(*) FILTER (WHERE activated_at IS NOT NULL) as used_keys
            FROM keys
        """)
        return {
            "summary": dict(summary),
            "top_wrong_questions": [dict(r) for r in top_wrong],
            "recent_logs": [dict(r) for r in recent_logs]
        }

@app.post("/api/admin/keys")
async def create_key(data: KeyCreate, request: Request):
    check_admin(request)
    chars = string.ascii_uppercase + string.digits
    key = "EP-" + "".join(secrets.choice(chars) for _ in range(12))
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO keys (key, owner_name, days) VALUES ($1, $2, $3)",
            key, data.owner_name, data.days
        )
    return {"success": True, "key": key, "owner_name": data.owner_name, "days": data.days}

@app.delete("/api/admin/keys/{key}")
async def delete_key(key: str, request: Request):
    check_admin(request)
    async with pool.acquire() as conn:
        await conn.execute("UPDATE keys SET is_active=FALSE WHERE key=$1", key)
    return {"success": True}

@app.post("/api/admin/keys/{key}/reactivate")
async def reactivate_key(key: str, request: Request):
    check_admin(request)
    async with pool.acquire() as conn:
        await conn.execute("UPDATE keys SET is_active=TRUE WHERE key=$1", key)
    return {"success": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)