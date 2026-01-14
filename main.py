import json
import datetime
import base64
import hashlib
from typing import Optional, List, Any

import jwt 
from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, Float, ForeignKey
from sqlalchemy.orm import sessionmaker, Session, relationship, declarative_base
from starlette.middleware.sessions import SessionMiddleware
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

# --- CONFIGURATION ---
SECRET_KEY = 'change-this-secret-key'
DATABASE_URL = "sqlite:///./web_traffic.db"

app = FastAPI()

# Add Session Middleware for login/logout and flash messages
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# Setup Templates
templates = Jinja2Templates(directory="templates")

# --- DATABASE SETUP ---
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- ENCRYPTION HELPER ---
def get_cipher():
    key = hashlib.sha256(SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))

# --- MODELS ---
class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(150), unique=True, nullable=False)
    password = Column(String(150), nullable=False)
    device_status = Column(Text, default="[]")
    # Set default to 1 hour ago so new users appear offline immediately
    last_seen = Column(DateTime, default=lambda: datetime.datetime.utcnow() - datetime.timedelta(hours=1))
    @property
    def is_authenticated(self):
        return True

class LogEntry(Base):
    __tablename__ = "log_entry"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    app_name = Column(String(100))
    download_speed = Column(Float)
    upload_speed = Column(Float)
    src_ip = Column(Text)
    dst_ip = Column(Text)

class CommandQueue(Base):
    __tablename__ = "command_queue"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    action = Column(String(50), nullable=False)
    target = Column(String(100), nullable=False)
    executed = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# --- DEPENDENCIES ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def flash(request: Request, message: str):
    if "_messages" not in request.session:
        request.session["_messages"] = []
    request.session["_messages"].append(message)

def get_flashed_messages(request: Request):
    return request.session.pop("_messages", [])

def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    user_id = request.session.get("user_id")
    if user_id:
        return db.query(User).filter(User.id == user_id).first()
    return None

# --- HELPER LOGIC ---
def get_dashboard_data_logic(user: User, db: Session):
    is_online = False
    if user and user.last_seen:
        is_online = (datetime.datetime.utcnow() - user.last_seen).total_seconds() < 30

    live_apps = []
    try:
        if user and user.device_status:
            loaded_data = json.loads(user.device_status)
            if isinstance(loaded_data, list):
                live_apps = [a for a in loaded_data if a.get('name') and a.get('name').lower() != 'ping']
                live_apps.sort(key=lambda x: x.get('down', 0), reverse=True)
    except:
        live_apps = []

    total_down = sum(a.get('down', 0) for a in live_apps)
    total_up = sum(a.get('up', 0) for a in live_apps)

    logs = []
    if is_online and user:
        logs = db.query(LogEntry).filter(
            LogEntry.user_id == user.id,
            LogEntry.app_name != 'ping'
        ).order_by(LogEntry.timestamp.desc()).limit(50).all()

        cipher = get_cipher()
        for log in logs:
            try:
                if log.dst_ip: log.dst_ip = cipher.decrypt(log.dst_ip.encode()).decode()
                if log.src_ip: log.src_ip = cipher.decrypt(log.src_ip.encode()).decode()
            except: pass

    return {
        'user': user,
        'current_user': user,
        'logs': logs,
        'live_apps': live_apps,
        'total_down': total_down,
        'total_up': total_up,
        'is_online': is_online
    }

# --- ROUTES ---

@app.get("/", response_class=RedirectResponse)
async def index(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)

# FIX: Added name="login" so url_for('login') works in templates
@app.get("/login", response_class=HTMLResponse, name="login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {
        "request": request, 
        "get_flashed_messages": lambda: get_flashed_messages(request)
    })

@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username).first()
    if user and check_password_hash(user.password, password):
        request.session["user_id"] = user.id
        return RedirectResponse(url="/dashboard", status_code=303)
    
    flash(request, "Invalid credentials")
    return templates.TemplateResponse("login.html", {
        "request": request,
        "get_flashed_messages": lambda: get_flashed_messages(request)
    })

# FIX: Added name="register" so url_for('register') works in templates
@app.get("/register", response_class=HTMLResponse, name="register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {
        "request": request,
        "get_flashed_messages": lambda: get_flashed_messages(request)
    })

@app.post("/register", response_class=HTMLResponse)
async def register_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    if db.query(User).filter(User.username == username).first():
        flash(request, "Username exists")
        return RedirectResponse(url="/register", status_code=303)
    
    hashed_pw = generate_password_hash(password, method='scrypt')
    new_user = User(username=username, password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    request.session["user_id"] = new_user.id
    return RedirectResponse(url="/dashboard", status_code=303)

@app.get("/logout", name="logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)

# --- DASHBOARD ---

@app.get("/dashboard", response_class=HTMLResponse, name="dashboard")
async def dashboard(
    request: Request, 
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    if request.headers.get('HX-Request'):
        return await dashboard_update(request, user, db)

    data = get_dashboard_data_logic(user, db)
    data["request"] = request
    data["get_flashed_messages"] = lambda: get_flashed_messages(request)
    
    return templates.TemplateResponse("dashboard.html", data)

@app.get("/dashboard/update", response_class=HTMLResponse, name="dashboard_update")
async def dashboard_update(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        response = RedirectResponse(url="/login")
        response.headers["HX-Redirect"] = "/login"
        return response

    data = get_dashboard_data_logic(user, db)
    data["request"] = request
    
    response = templates.TemplateResponse("dashboard_content.html", data)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.get("/dashboard/kill/{app_name}", name="kill_app")
async def kill_app(
    app_name: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse(url="/login", status_code=302)
        
    cmd = CommandQueue(user_id=user.id, action='kill', target=app_name)
    db.add(cmd)
    db.commit()
    
    flash(request, f"Command sent to close {app_name}")
    return RedirectResponse(url="/dashboard", status_code=303)

# --- API FOR DESKTOP ---

@app.post("/api/login")
async def api_login(
    request: Request, 
    db: Session = Depends(get_db)
):
    data = await request.json()
    username = data.get('username')
    password = data.get('password')
    
    user = db.query(User).filter(User.username == username).first()
    if user and check_password_hash(user.password, password):
        token = jwt.encode(
            {
                'user_id': user.id, 
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, 
            SECRET_KEY, 
            algorithm="HS256"
        )
        if isinstance(token, bytes):
            token = token.decode('utf-8')
            
        return {"access_token": token}
        
    return JSONResponse(status_code=401, content={'message': 'Invalid credentials'})

@app.post("/api/sync")
async def api_sync(
    request: Request,
    db: Session = Depends(get_db)
):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={'message': 'Missing token'})
    
    try:
        token = auth_header.split(" ")[1]
        data_jwt = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        api_user = db.query(User).get(data_jwt['user_id'])
        if not api_user:
            raise Exception("User not found")
    except:
        return JSONResponse(status_code=401, content={'message': 'Invalid token'})

    data = await request.json()
    cipher = get_cipher()

    for log in data.get('logs', []):
        if log[1].lower() == 'ping': continue
        try:
            enc_src = cipher.encrypt(str(log[4]).encode()).decode()
            enc_dst = cipher.encrypt(str(log[5]).encode()).decode()
            
            new_log = LogEntry(
                user_id=api_user.id, 
                timestamp=datetime.datetime.fromtimestamp(log[0]), 
                app_name=log[1], 
                download_speed=log[2], 
                upload_speed=log[3], 
                src_ip=enc_src, 
                dst_ip=enc_dst
            )
            db.add(new_log)
        except Exception as e:
            print(f"Error processing log: {e}")
    
    raw_status = data.get('status', [])
    clean_status = [s for s in raw_status if s.get('name', '').lower() != 'ping']
    api_user.device_status = json.dumps(clean_status)
    api_user.last_seen = datetime.datetime.utcnow()
    
    pending_cmds = db.query(CommandQueue).filter_by(user_id=api_user.id, executed=False).all()
    commands = [{"action": c.action, "target": c.target} for c in pending_cmds]
    
    for c in pending_cmds:
        c.executed = True
    
    db.commit()
    return {'status': 'success', 'commands': commands}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=True)