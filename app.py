import json
import datetime
from functools import wraps
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///web_traffic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    # Stores the last received live status (JSON)
    device_status = db.Column(db.Text, default="[]") 
    last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    app_name = db.Column(db.String(100))
    download_speed = db.Column(db.Float)
    upload_speed = db.Column(db.Float)
    src_ip = db.Column(db.String(50))
    dst_ip = db.Column(db.String(50))

class CommandQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False) # e.g., 'kill'
    target = db.Column(db.String(100), nullable=False) # e.g., 'chrome.exe'
    executed = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/')
def index():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
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

# Make sure you have this import at the top of app.py
import datetime 

@app.route('/dashboard')
@login_required
def dashboard():
    # Parse live status
    live_apps = []
    try:
        if current_user.device_status:
            live_apps = json.loads(current_user.device_status)
            # Sort by download speed
            live_apps.sort(key=lambda x: x['down'], reverse=True)
    except: pass

    # Calculate totals for graph
    total_down = sum(a['down'] for a in live_apps)
    total_up = sum(a['up'] for a in live_apps)

    logs = LogEntry.query.filter_by(user_id=current_user.id).order_by(LogEntry.timestamp.desc()).limit(50).all()
    
    return render_template('dashboard.html', 
                         user=current_user, 
                         logs=logs, 
                         live_apps=live_apps,
                         total_down=total_down,
                         total_up=total_up,
                         datetime=datetime.datetime) # <--- THIS LINE FIXES THE ERROR
@app.route('/dashboard/kill/<path:app_name>')
@login_required
def kill_app(app_name):
    # Queue the command for the desktop app to pick up
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
    # Verify Token manually or use decorator
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
    
    # 1. Save Logs
    for log in data.get('logs', []):
        db.session.add(LogEntry(
            user_id=api_user.id, timestamp=datetime.datetime.fromtimestamp(log[0]),
            app_name=log[1], download_speed=log[2], upload_speed=log[3], src_ip=log[4], dst_ip=log[5]
        ))
    
    # 2. Update Live Status
    api_user.device_status = json.dumps(data.get('status', []))
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