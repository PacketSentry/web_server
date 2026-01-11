import json
import datetime
import base64
import hashlib
from functools import wraps
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet #

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-secret-key' # Ensure this is secure in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///web_traffic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- ENCRYPTION HELPER ---
def get_cipher():
    # Generate a valid 32-byte key from the SECRET_KEY
    key = hashlib.sha256(app.config['SECRET_KEY'].encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    device_status = db.Column(db.Text, default="[]") 
    last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    app_name = db.Column(db.String(100))
    download_speed = db.Column(db.Float)
    upload_speed = db.Column(db.Float)
    # Changed to Text to hold long encrypted strings
    src_ip = db.Column(db.Text) 
    dst_ip = db.Column(db.Text) 

class CommandQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(100), nullable=False)
    executed = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/')
def index():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('login'))

# In app.py

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            # FIX: Check if the 'remember' box was ticked
            remember = True if request.form.get('remember') else False
            
            # Pass the remember status to Flask-Login
            login_user(user, remember=remember)
            
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form.get('username')).first():
            flash('Username exists')
            return redirect(url_for('register'))
        new_user = User(username=request.form.get('username'), password=generate_password_hash(request.form.get('password'), method='scrypt'))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# In app.py

@app.route('/dashboard')
@login_required
def dashboard():
    # 1. Calculate Online Status (Online if seen in last 30 seconds)
    is_online = False
    if current_user.last_seen:
        # datetime.datetime.utcnow() matches the DB default
        is_online = (datetime.datetime.utcnow() - current_user.last_seen).total_seconds() < 30

    # 2. Parse live status safely
    live_apps = []
    try:
        if current_user.device_status:
            loaded_data = json.loads(current_user.device_status)
            if isinstance(loaded_data, list):
                # Filter 'ping' and ghosts
                live_apps = [a for a in loaded_data if a.get('name') and a.get('name').lower() != 'ping']
                live_apps.sort(key=lambda x: x.get('down', 0), reverse=True)
    except: 
        live_apps = []

    # 3. Calculate totals
    total_down = sum(a.get('down', 0) for a in live_apps)
    total_up = sum(a.get('up', 0) for a in live_apps)

    # 4. Fetch Logs (Only if online, otherwise empty list to hide history)
    # The user asked to "not show history", we handle visual hiding in template, 
    # but we can also optimize here.
    logs = []
    if is_online:
        logs = LogEntry.query.filter(
            LogEntry.user_id == current_user.id, 
            LogEntry.app_name != 'ping'
        ).order_by(LogEntry.timestamp.desc()).limit(50).all()

        # Decrypt IPs (Keep your existing encryption logic)
        cipher = get_cipher()
        for log in logs:
            try:
                if log.dst_ip: log.dst_ip = cipher.decrypt(log.dst_ip.encode()).decode()
                if log.src_ip: log.src_ip = cipher.decrypt(log.src_ip.encode()).decode()
            except: pass

    # 5. Render Response
    # If request comes from HTMX (dynamic refresh), return only the content partial
    if request.headers.get('HX-Request'):
        return render_template('dashboard_content.html', 
                             user=current_user, logs=logs, live_apps=live_apps, 
                             total_down=total_down, total_up=total_up, 
                             is_online=is_online)
    
    # Otherwise render the full dashboard shell
    return render_template('dashboard.html', 
                         user=current_user, logs=logs, live_apps=live_apps, 
                         total_down=total_down, total_up=total_up, 
                         is_online=is_online)

@app.route('/dashboard/kill/<path:app_name>')
@login_required
def kill_app(app_name):
    cmd = CommandQueue(user_id=current_user.id, action='kill', target=app_name)
    db.session.add(cmd)
    db.session.commit()
    flash(f"Command sent to close {app_name}")
    return redirect(url_for('dashboard'))

# --- API FOR DESKTOP ---

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if user and check_password_hash(user.password, data.get('password')):
        import jwt
        token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'access_token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/sync', methods=['POST'])
def api_sync():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({'message': 'Missing token'}), 401
    
    try:
        import jwt
        token = auth_header.split(" ")[1]
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        api_user = User.query.get(data['user_id'])
    except: return jsonify({'message': 'Invalid token'}), 401

    data = request.json
    cipher = get_cipher() # Initialize cipher

    # 1. Save Logs (Encrypt IPs)
    for log in data.get('logs', []):
        if log[1].lower() == 'ping': continue
        
        # Encrypt src (log[4]) and dst (log[5])
        # We assume they are strings; encrypt() returns bytes, decode to store as string
        enc_src = cipher.encrypt(str(log[4]).encode()).decode()
        enc_dst = cipher.encrypt(str(log[5]).encode()).decode()

        db.session.add(LogEntry(
            user_id=api_user.id, 
            timestamp=datetime.datetime.fromtimestamp(log[0]),
            app_name=log[1], 
            download_speed=log[2], 
            upload_speed=log[3], 
            src_ip=enc_src, 
            dst_ip=enc_dst
        ))
    
    # 2. Update Live Status
    raw_status = data.get('status', [])
    clean_status = [s for s in raw_status if s.get('name', '').lower() != 'ping']
    api_user.device_status = json.dumps(clean_status)
    api_user.last_seen = datetime.datetime.utcnow()
    
    # 3. Fetch Pending Commands
    pending_cmds = CommandQueue.query.filter_by(user_id=api_user.id, executed=False).all()
    commands = [{"action": c.action, "target": c.target} for c in pending_cmds]
    for c in pending_cmds: c.executed = True
    
    db.session.commit()
    return jsonify({'status': 'success', 'commands': commands})

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True, port=5000, host='0.0.0.0') 