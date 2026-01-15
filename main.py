from fastapi import FastAPI, Request, Depends, HTTPException, status, Header, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import List, Optional
import time
import os
import json
from cryptography.fernet import Fernet

# --- ENCRYPTION SETUP ---
KEY_FILE = "secret.key"
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f: f.write(key)
else:
    with open(KEY_FILE, "rb") as f: key = f.read()

cipher = Fernet(key)

# --- DATABASE SETUP ---
DATABASE_URL = "sqlite:///./cloud_db.sqlite"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class TrafficLog(Base):
    __tablename__ = "traffic_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    timestamp = Column(Float)
    app_name = Column(String)
    packet_size = Column(Integer)
    direction = Column(String)
    ip_address = Column(String)

class ClientStatus(Base):
    __tablename__ = "client_status"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    last_seen = Column(Float)
    is_online = Column(Integer)
    top_app = Column(String, default="---")
    current_down = Column(Float, default=0.0)
    current_up = Column(Float, default=0.0)
    app_list_json = Column(String, default="[]") 

Base.metadata.create_all(bind=engine)

# --- APP SETUP ---
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"

# --- HELPERS ---
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token: return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username: return None
    except JWTError: return None
    return db.query(User).filter(User.username == username).first()

def api_get_user(authorization: str = None, db: Session = Depends(get_db)):
    if not authorization: raise HTTPException(status_code=401)
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        return db.query(User).filter(User.username == username).first()
    except: raise HTTPException(status_code=401)

class SyncPayload(BaseModel):
    status: Optional[List[dict]] = None
    logs: Optional[List[list]] = None 

# --- ROUTES ---

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user: return templates.TemplateResponse("login.html", {"request": request})
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

# --- NEW: JSON API FOR DYNAMIC UPDATES ---
@app.get("/api/dashboard-data")
async def get_dashboard_data(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user: return JSONResponse({"error": "Unauthorized"}, status_code=401)
    
    # 1. Fetch Logs
    logs = db.query(TrafficLog).filter(TrafficLog.user_id == user.id).order_by(TrafficLog.id.desc()).limit(20).all()
    decrypted_logs = []
    for l in logs:
        try: dec_ip = cipher.decrypt(l.ip_address.encode()).decode()
        except: dec_ip = "Error"
        decrypted_logs.append({
            "timestamp": time.strftime('%H:%M:%S', time.localtime(l.timestamp)),
            "app_name": l.app_name,
            "packet_size": l.packet_size,
            "direction": l.direction,
            "ip_address": dec_ip
        })

    # 2. Fetch Status
    status_entry = db.query(ClientStatus).filter(ClientStatus.user_id == user.id).first()
    data = {
        "is_online": False,
        "last_seen": 0,
        "top_app": "---",
        "current_down": 0.0,
        "current_up": 0.0,
        "app_list": [],
        "logs": decrypted_logs
    }

    if status_entry:
        data["last_seen"] = status_entry.last_seen
        data["top_app"] = status_entry.top_app
        data["current_down"] = status_entry.current_down
        data["current_up"] = status_entry.current_up
        
        if time.time() - status_entry.last_seen < 5:
            data["is_online"] = True
            try:
                if status_entry.app_list_json:
                    app_list = json.loads(status_entry.app_list_json)
                    app_list.sort(key=lambda x: (-x['down'], x['name'].lower()))
                    data["app_list"] = app_list
            except: pass
            
    return JSONResponse(data)

# --- REGISTER ---
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register_action(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if len(password.encode('utf-8')) > 72:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Password too long (max 72 bytes)"})

    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Username taken"})
    
    hashed_pw = pwd_context.hash(password)
    new_user = User(username=username, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    
    return templates.TemplateResponse("login.html", {"request": request, "success": "Account created! Please login."})

# --- LOGIN (WEB) ---
@app.post("/login")
async def login_web(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if len(password.encode('utf-8')) > 72:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid Credentials"})

    user = db.query(User).filter(User.username == username).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid Credentials"})
    
    access_token = jwt.encode({"sub": user.username}, SECRET_KEY, algorithm=ALGORITHM)
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key="access_token", value=access_token)
    return response

# --- LOGIN (API) ---
@app.post("/api/login")
async def login_api(request: Request, db: Session = Depends(get_db)):
    try: data = await request.json()
    except: raise HTTPException(status_code=400, detail="Invalid JSON")

    password = data.get('password')
    if not password or len(password.encode('utf-8')) > 72:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    user = db.query(User).filter(User.username == data.get('username')).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect credentials")
    
    access_token = jwt.encode({"sub": user.username}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token}

# --- SYNC (API) ---
@app.post("/api/sync")
async def sync_data(payload: SyncPayload, authorization: str = Header(None), db: Session = Depends(get_db)):
    user = api_get_user(authorization, db)
    if not user: return {"error": "unauthorized"}

    if payload.status is not None:
        stat_entry = db.query(ClientStatus).filter(ClientStatus.user_id == user.id).first()
        if not stat_entry:
            stat_entry = ClientStatus(user_id=user.id)
            db.add(stat_entry)
        
        stat_entry.last_seen = time.time()
        stat_entry.is_online = 1
        stat_entry.current_down = sum(x['down'] for x in payload.status)
        stat_entry.current_up = sum(x['up'] for x in payload.status)
        stat_entry.app_list_json = json.dumps(payload.status)
        
        if payload.status:
            top = max(payload.status, key=lambda x: x['down'] + x['up'])
            stat_entry.top_app = top['name']
        db.commit()

    if payload.logs:
        for row in payload.logs:
            try:
                enc_ip = cipher.encrypt(row[4].encode()).decode()
                log = TrafficLog(
                    user_id=user.id,
                    timestamp=row[0],
                    app_name=row[1],
                    packet_size=int(row[2]),
                    direction=row[3],
                    ip_address=enc_ip
                )
                db.add(log)
            except: pass
        db.commit()

    return {"status": "ok"}

@app.get("/logout")
async def logout(request: Request):
    response = templates.TemplateResponse("login.html", {"request": request})
    response.delete_cookie("access_token")
    return response

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)