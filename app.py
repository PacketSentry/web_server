import os
import secrets
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Initialize App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///web_traffic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=False)
    logs = db.relationship('LogEntry', backref='user', lazy=True)

class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    app_name = db.Column(db.String(100))
    download_speed = db.Column(db.Float)
    upload_speed = db.Column(db.Float)
    src_ip = db.Column(db.String(50))
    dst_ip = db.Column(db.String(50))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        
        new_user = User(
            username=username, 
            password=generate_password_hash(password, method='scrypt'),
            api_key=secrets.token_hex(16)
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch latest 100 logs for this user
    logs = LogEntry.query.filter_by(user_id=current_user.id).order_by(LogEntry.timestamp.desc()).limit(100).all()
    return render_template('dashboard.html', user=current_user, logs=logs)

# --- API FOR DESKTOP APP ---
@app.route('/api/upload', methods=['POST'])
def upload_logs():
    data = request.json
    api_key = data.get('api_key')
    logs = data.get('logs', [])
    
    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return jsonify({'error': 'Invalid API Key'}), 401
    
    for log in logs:
        # log format: [timestamp, app_name, down, up, src, dst]
        entry = LogEntry(
            user_id=user.id,
            timestamp=datetime.fromtimestamp(log[0]),
            app_name=log[1],
            download_speed=log[2],
            upload_speed=log[3],
            src_ip=log[4],
            dst_ip=log[5]
        )
        db.session.add(entry)
    
    db.session.commit()
    return jsonify({'status': 'success', 'count': len(logs)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)