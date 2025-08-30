import eventlet
eventlet.monkey_patch()

import os
import secrets
import string
import smtplib
import logging
import json
import base64
import mimetypes
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
from werkzeug.utils import secure_filename
import html
import re
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'e4a7f4f38d5a6c92b1f8b86a9aee79e52e4e0a53c493b6a30a6f2a2c8912bda4')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet", max_http_buffer_size=50*1024*1024)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cipherchat.log'),
        logging.StreamHandler()
    ]
)

# Create necessary directories
UPLOAD_FOLDER = Path('uploads')
PROFILE_FOLDER = Path('uploads/profiles')
MEDIA_FOLDER = Path('uploads/media')

for folder in [UPLOAD_FOLDER, PROFILE_FOLDER, MEDIA_FOLDER]:
    folder.mkdir(exist_ok=True)

# Enhanced In-memory storage (in production, use Redis/PostgreSQL)
class DataStore:
    def __init__(self):
        # User management
        self.users = {}  # {email: {username, email, avatar_url, created_at, last_seen}}
        self.user_sessions = {}  # {session_id: user_email}
        
        # Authentication
        self.otp_storage = {}
        self.dynamic_passwords = {}
        self.rate_limits = defaultdict(list)
        
        # Chat system
        self.rooms = {}  # {room_id: {name, type, participants, created_by, created_at}}
        self.messages = defaultdict(list)  # {room_id: [messages]}
        self.active_users = {}  # {session_id: {email, username, rooms, last_activity}}
        
        # Media and files
        self.media_files = {}  # {file_id: {filename, filepath, mime_type, uploaded_by, uploaded_at}}
        
        # Invites
        self.invite_links = {}
        
        # User conversations
        self.user_conversations = defaultdict(set)  # {email: {room_ids}}
        
        # Typing indicators
        self.typing_users = defaultdict(set)  # {room_id: {user_emails}}

    def add_user(self, email, username, avatar_url=None):
        """Add or update user"""
        self.users[email] = {
            'username': username,
            'email': email,
            'avatar_url': avatar_url,
            'created_at': datetime.now(),
            'last_seen': datetime.now()
        }
        return self.users[email]
    
    def get_user(self, email):
        """Get user by email"""
        return self.users.get(email)
    
    def update_last_seen(self, email):
        """Update user's last seen timestamp"""
        if email in self.users:
            self.users[email]['last_seen'] = datetime.now()
    
    def add_user_to_room(self, email, room_id):
        """Add user to room"""
        self.user_conversations[email].add(room_id)
        if room_id in self.rooms:
            if email not in self.rooms[room_id]['participants']:
                self.rooms[room_id]['participants'].append(email)
    
    def create_room(self, room_id, name, room_type, created_by, participants=None):
        """Create a new room"""
        self.rooms[room_id] = {
            'id': room_id,
            'name': name,
            'type': room_type,  # 'group' or 'direct'
            'participants': participants or [created_by],
            'created_by': created_by,
            'created_at': datetime.now(),
            'description': ''
        }
        
        # Add all participants to room
        for email in self.rooms[room_id]['participants']:
            self.user_conversations[email].add(room_id)
        
        return self.rooms[room_id]
    
    def add_message(self, room_id, sender_email, message_type, content, media_info=None):
        """Add message to room"""
        message_data = {
            'id': secrets.token_urlsafe(16),
            'room_id': room_id,
            'sender_email': sender_email,
            'sender_username': self.users.get(sender_email, {}).get('username', 'Unknown'),
            'type': message_type,  # 'text' or 'media'
            'content': content,
            'timestamp': datetime.now().isoformat(),
            'status': 'sent'
        }
        
        if media_info:
            message_data.update(media_info)
        
        self.messages[room_id].append(message_data)
        
        # Keep only last 1000 messages per room
        if len(self.messages[room_id]) > 1000:
            self.messages[room_id] = self.messages[room_id][-1000:]
        
        return message_data
    
    def get_user_rooms(self, email):
        """Get all rooms for a user"""
        user_room_ids = self.user_conversations.get(email, set())
        user_rooms = []
        
        for room_id in user_room_ids:
            if room_id in self.rooms:
                room = self.rooms[room_id].copy()
                
                # Get last message
                room_messages = self.messages.get(room_id, [])
                room['last_message'] = room_messages[-1] if room_messages else None
                room['last_activity'] = room_messages[-1]['timestamp'] if room_messages else room['created_at'].isoformat()
                
                # Calculate unread count (simplified - in production use proper read receipts)
                room['unread_count'] = 0  # Implement proper unread logic
                
                # Add participant details
                room['participants'] = [self.users.get(email, {'username': 'Unknown', 'email': email}) 
                                       for email in room['participants'] if email in self.users]
                room['participant_count'] = len(room['participants'])
                
                user_rooms.append(room)
        
        # Sort by last activity
        user_rooms.sort(key=lambda x: x['last_activity'], reverse=True)
        return user_rooms

# Initialize data store
db = DataStore()

# Email configuration
SMTP_EMAIL = os.getenv('SMTP_EMAIL', 'gaminghatyar777@gmail.com')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', 'xvjxaszgbseqjwon')
ADMIN_EMAIL = 'spideyofficial777@gmail.com'
MASTER_PASSWORD = os.getenv('MASTER_PASSWORD', 'love123')
BASE_URL = os.getenv('BASE_URL', 'http://localhost:5000')

# Allowed file extensions
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'webm', 'mov', 'avi'}

def is_rate_limited(email):
    """Check if email is rate limited"""
    now = datetime.now()
    hour_ago = now - timedelta(hours=1)
    db.rate_limits[email] = [ts for ts in db.rate_limits[email] if ts > hour_ago]
    return len(db.rate_limits[email]) >= 5

def add_rate_limit(email):
    """Add rate limit entry"""
    db.rate_limits[email].append(datetime.now())

def generate_otp():
    """Generate secure 6-digit OTP"""
    return ''.join(secrets.choice(string.digits) for _ in range(6))

def generate_dynamic_password():
    """Generate secure dynamic password"""
    length = secrets.randbelow(3) + 10
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_room_id():
    """Generate unique room ID"""
    return secrets.token_urlsafe(16)

def generate_invite_code():
    """Generate secure invite code"""
    return secrets.token_urlsafe(24)

def allowed_file(filename, file_type='image'):
    """Check if file extension is allowed"""
    if '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    if file_type == 'image':
        return ext in ALLOWED_IMAGE_EXTENSIONS
    elif file_type == 'video':
        return ext in ALLOWED_VIDEO_EXTENSIONS
    return False

def save_uploaded_file(file, file_type='media'):
    """Save uploaded file and return file info"""
    if not file or file.filename == '':
        return None
    
    filename = secure_filename(file.filename)
    file_id = secrets.token_urlsafe(16)
    
    # Add timestamp to filename to avoid conflicts
    name, ext = os.path.splitext(filename)
    new_filename = f"{file_id}_{name}{ext}"
    
    if file_type == 'profile':
        filepath = PROFILE_FOLDER / new_filename
    else:
        filepath = MEDIA_FOLDER / new_filename
    
    try:
        file.save(filepath)
        
        file_info = {
            'file_id': file_id,
            'original_filename': filename,
            'filename': new_filename,
            'filepath': str(filepath),
            'mime_type': file.mimetype or mimetypes.guess_type(filename)[0],
            'size': os.path.getsize(filepath),
            'uploaded_at': datetime.now().isoformat()
        }
        
        db.media_files[file_id] = file_info
        return file_info
        
    except Exception as e:
        logging.error(f"Failed to save file {filename}: {str(e)}")
        return None

def send_email(to_email, subject, html_body):
    """Enhanced email sending with better error handling"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"CipherChat <{SMTP_EMAIL}>"
        msg['To'] = to_email
        
        text_part = MIMEText("Please view this email in an HTML-compatible email client.", 'plain')
        html_part = MIMEText(html_body, 'html')
        
        msg.attach(text_part)
        msg.attach(html_part)
        
        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(SMTP_EMAIL, SMTP_PASSWORD)
                server.send_message(msg)
                logging.info(f"Email sent to: {to_email}")
                return True
        except Exception as ssl_error:
            logging.warning(f"SSL failed, trying TLS: {ssl_error}")
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(SMTP_EMAIL, SMTP_PASSWORD)
                server.send_message(msg)
                logging.info(f"Email sent via TLS to: {to_email}")
                return True
                
    except Exception as e:
        logging.error(f"Email send failed: {str(e)}")
        return False

def create_otp_email(otp: str, username: str) -> str:
    """Enhanced OTP email template"""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Your Secure OTP Code</title>
        <style>
            body {{
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #333;
            }}
            .container {{
                max-width: 650px;
                margin: 0 auto;
                padding: 30px 20px;
            }}
            .card {{
                background: rgba(255, 255, 255, 0.97);
                border-radius: 25px;
                padding: 45px;
                box-shadow: 0 25px 50px rgba(0,0,0,0.15);
                backdrop-filter: blur(12px);
                text-align: center;
            }}
            .logo {{
                font-size: 38px;
                font-weight: 900;
                background: linear-gradient(90deg, #667eea, #764ba2);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 20px;
            }}
            .greeting {{
                font-size: 22px;
                color: #333;
                margin-bottom: 15px;
            }}
            .otp-box {{
                display: inline-block;
                background: linear-gradient(135deg, #25d366, #128c7e);
                color: white;
                font-size: 32px;
                font-weight: bold;
                padding: 20px 40px;
                border-radius: 15px;
                letter-spacing: 8px;
                margin: 20px 0;
                box-shadow: 0 10px 30px rgba(37, 211, 102, 0.4);
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <div class="logo">🔐 CipherChat</div>
                <div class="greeting">Hello {username}!</div>
                <p>Your verification code is:</p>
                <div class="otp-box">{otp}</div>
                <p><strong>This code expires in 5 minutes.</strong></p>
                <p style="color: #666; font-size: 14px;">If you didn't request this code, please ignore this email.</p>
            </div>
        </div>
    </body>
    </html>
    """

def sanitize_message(message):
    """Sanitize message content"""
    return html.escape(message.strip())

def get_user_initials(username):
    """Get user initials for avatar"""
    return ''.join(word[0].upper() for word in username.split()[:2])

# Routes
@app.route('/')
def index():
    if 'authenticated' in session and session['authenticated']:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        # Validate inputs
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return render_template('login.html')
        
        try:
            validate_email(email)
        except EmailNotValidError:
            flash('Invalid email format!', 'error')
            return render_template('login.html')
        
        if password != MASTER_PASSWORD:
            flash('Invalid master password!', 'error')
            logging.warning(f"Invalid master password for: {email}")
            return render_template('login.html')
        
        if is_rate_limited(email):
            flash('Too many OTP requests. Please try again later.', 'error')
            return render_template('login.html')
        
        # Add/update user in database
        db.add_user(email, username)
        
        # Generate OTP
        otp = generate_otp()
        db.otp_storage[email] = {
            'otp': otp,
            'expires': datetime.now() + timedelta(minutes=5),
            'attempts': 0
        }
        
        # Send OTP email
        html_body = create_otp_email(otp, username)
        if send_email(email, 'Your CipherChat OTP Code', html_body):
            add_rate_limit(email)
            session['email'] = email
            session['username'] = username
            session['otp_sent'] = True
            flash('OTP sent to your email!', 'success')
            return redirect(url_for('verify_otp'))
        else:
            flash('Failed to send OTP. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'email' not in session:
        return redirect(url_for('login'))
    
    email = session['email']
    
    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        
        if email not in db.otp_storage:
            flash('OTP expired. Please login again.', 'error')
            return redirect(url_for('login'))
        
        otp_data = db.otp_storage[email]
        
        if datetime.now() > otp_data['expires']:
            del db.otp_storage[email]
            flash('OTP expired. Please login again.', 'error')
            return redirect(url_for('login'))
        
        if otp_data['attempts'] >= 3:
            del db.otp_storage[email]
            flash('Too many failed attempts. Please login again.', 'error')
            return redirect(url_for('login'))
        
        if entered_otp == otp_data['otp']:
            dynamic_pass = generate_dynamic_password()
            db.dynamic_passwords[email] = {
                'password': dynamic_pass,
                'expires': datetime.now() + timedelta(minutes=5)
            }
            
            del db.otp_storage[email]
            session['otp_verified'] = True
            session['dynamic_password'] = dynamic_pass
            flash('OTP verified! Here is your dynamic password.', 'success')
            return redirect(url_for('dynamic_verify'))
        else:
            otp_data['attempts'] += 1
            flash('Invalid OTP. Please try again.', 'error')
    
    return render_template('verify_otp.html')

@app.route('/dynamic-verify', methods=['GET', 'POST'])
def dynamic_verify():
    if 'email' not in session or 'otp_verified' not in session:
        return redirect(url_for('login'))
    
    email = session['email']
    
    if request.method == 'POST':
        entered_password = request.form.get('dynamic_password', '').strip()
        
        if email not in db.dynamic_passwords:
            flash('Dynamic password expired. Please login again.', 'error')
            return redirect(url_for('login'))
        
        pass_data = db.dynamic_passwords[email]
        
        if datetime.now() > pass_data['expires']:
            del db.dynamic_passwords[email]
            flash('Dynamic password expired. Please login again.', 'error')
            return redirect(url_for('login'))
        
        if entered_password == pass_data['password']:
            del db.dynamic_passwords[email]
            
            session['authenticated'] = True
            session['user_email'] = email
            
            # Update user last seen
            db.update_last_seen(email)
            
            # Create general room if doesn't exist
            if 'general' not in db.rooms:
                db.create_room('general', 'General Chat', 'group', email)
            
            # Add user to general room
            db.add_user_to_room(email, 'general')
            
            flash('Authentication successful! Welcome to CipherChat.', 'success')
            logging.info(f"User authenticated: {email}")
            return redirect(url_for('chat'))
        else:
            flash('Invalid dynamic password!', 'error')
    
    return render_template('dynamic_verify.html')

@app.route('/chat')
def chat():
    if 'authenticated' not in session or not session['authenticated']:
        return redirect(url_for('login'))
    
    user_email = session['user_email']
    user_data = db.get_user(user_email)
    
    return render_template('chat.html', 
                         user_email=user_email,
                         username=user_data['username'] if user_data else 'Unknown User')

@app.route('/upload-profile-picture', methods=['POST'])
def upload_profile_picture():
    if 'authenticated' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'})
    
    file = request.files['file']
    if not allowed_file(file.filename, 'image'):
        return jsonify({'success': False, 'message': 'Invalid file type'})
    
    file_info = save_uploaded_file(file, 'profile')
    if file_info:
        user_email = session['user_email']
        user = db.get_user(user_email)
        if user:
            user['avatar_url'] = f"/uploads/profiles/{file_info['filename']}"
            return jsonify({'success': True, 'avatar_url': user['avatar_url']})
    
    return jsonify({'success': False, 'message': 'Failed to upload file'})

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    file_path = UPLOAD_FOLDER / filename
    if file_path.exists():
        return send_file(file_path)
    return "File not found", 404

@app.route('/create-group', methods=['POST'])
def create_group():
    if 'authenticated' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    data = request.get_json()
    group_name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    members = data.get('members', [])
    creator_email = session['user_email']
    
    if not group_name:
        return jsonify({'success': False, 'message': 'Group name is required'})
    
    # Add creator to members
    if creator_email not in members:
        members.append(creator_email)
    
    # Create group room
    room_id = generate_room_id()
    group_data = db.create_room(room_id, group_name, 'group', creator_email, members)
    group_data['description'] = description
    
    return jsonify({'success': True, 'group': {
        'id': room_id,
        'name': group_name,
        'description': description,
        'members': [db.get_user(email) for email in members if db.get_user(email)],
        'created_by': creator_email
    }})

@app.route('/logout')
def logout():
    email = session.get('user_email')
    if email:
        db.update_last_seen(email)
        logging.info(f"User logged out: {email}")
    
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

# Enhanced SocketIO Events
@socketio.on('connect')
def on_connect():
    if 'authenticated' not in session or not session['authenticated']:
        return False
    
    user_email = session['user_email']
    user_data = db.get_user(user_email)
    
    if not user_data:
        return False
    
    # Add to active users
    db.active_users[request.sid] = {
        'email': user_email,
        'username': user_data['username'],
        'avatar_url': user_data.get('avatar_url'),
        'rooms': set(),
        'last_activity': datetime.now()
    }
    
    # Update user last seen
    db.update_last_seen(user_email)
    
    logging.info(f"User connected: {user_email}")

@socketio.on('disconnect')
def on_disconnect():
    if request.sid in db.active_users:
        user_data = db.active_users[request.sid]
        user_email = user_data['email']
        
        # Leave all rooms
        for room_id in user_data['rooms']:
            leave_room(room_id)
            emit('user_left', {
                'email': user_email,
                'username': user_data['username'],
                'room': room_id
            }, room=room_id)
        
        # Remove from active users
        del db.active_users[request.sid]
        
        # Update last seen
        db.update_last_seen(user_email)
        
        # Broadcast updated user list
        broadcast_active_users()
        logging.info(f"User disconnected: {user_email}")

@socketio.on('get_current_user')
def get_current_user():
    if 'authenticated' not in session:
        return
    
    user_email = session['user_email']
    user_data = db.get_user(user_email)
    
    if user_data:
        emit('current_user', {
            'username': user_data['username'],
            'email': user_data['email'],
            'avatar': user_data.get('avatar_url')
        })

@socketio.on('get_active_users')
def get_active_users():
    """Send list of currently active users"""
    active_users_list = []
    for session_data in db.active_users.values():
        user_info = {
            'username': session_data['username'],
            'email': session_data['email'],
            'avatar': session_data.get('avatar_url'),
            'last_activity': session_data['last_activity'].isoformat()
        }
        active_users_list.append(user_info)
    
    emit('active_users', {'users': active_users_list})

@socketio.on('get_user_conversations')
def get_user_conversations():
    if 'authenticated' not in session:
        return
    
    user_email = session['user_email']
    user_rooms = db.get_user_rooms(user_email)
    
    emit('user_conversations', {'conversations': user_rooms})

@socketio.on('join_room')
def on_join_room(data):
    if 'authenticated' not in session:
        return
    
    room_id = data['room']
    user_email = session['user_email']
    
    if request.sid not in db.active_users:
        return
    
    # Check if user has access to this room
    if room_id not in db.user_conversations.get(user_email, set()):
        emit('error', {'message': 'Access denied to this room'})
        return
    
    join_room(room_id)
    db.active_users[request.sid]['rooms'].add(room_id)
    
    # Send room history
    room_messages = db.messages.get(room_id, [])[-50:]  # Last 50 messages
    emit('room_history', {'messages': room_messages})
    
    # Notify others
    user_data = db.active_users[request.sid]
    emit('user_joined', {
        'email': user_email,
        'username': user_data['username'],
        'room': room_id
    }, room=room_id, include_self=False)

@socketio.on('leave_room')
def on_leave_room(data):
    if 'authenticated' not in session:
        return
    
    room_id = data['room']
    user_email = session['user_email']
    
    if request.sid in db.active_users:
        db.active_users[request.sid]['rooms'].discard(room_id)
    
    leave_room(room_id)
    
    # Stop typing if user was typing
    if user_email in db.typing_users[room_id]:
        db.typing_users[room_id].discard(user_email)
        emit('stop_typing', {'room': room_id}, room=room_id)

@socketio.on('send_message')
def handle_send_message(data):
    if 'authenticated' not in session:
        return
    
    user_email = session['user_email']
    room_id = data.get('room')
    message_content = sanitize_message(data.get('message', ''))
    
    if not message_content.strip() or not room_id:
        return
    
    # Verify user has access to room
    if room_id not in db.user_conversations.get(user_email, set()):
        return
    
    # Add message to database
    message_data = db.add_message(room_id, user_email, 'text', message_content)
    
    # Broadcast message to room
    emit('receive_message', message_data, room=room_id)
    
    logging.info(f"Message sent by {user_email} to room {room_id}")

@socketio.on('send_media')
def handle_send_media(data):
    if 'authenticated' not in session:
        return
    
    user_email = session['user_email']
    room_id = data.get('room')
    media_data = data.get('media_data')  # Base64 encoded
    media_type = data.get('media_type')
    media_name = data.get('media_name')
    caption = sanitize_message(data.get('caption', ''))
    
    if not room_id or not media_data:
        return
    
    # Verify user has access to room
    if room_id not in db.user_conversations.get(user_email, set()):
        return
    
    try:
        # Decode base64 media
        header, encoded = media_data.split(',', 1)
        media_bytes = base64.b64decode(encoded)
        
        # Generate filename
        file_id = secrets.token_urlsafe(16)
        ext = media_name.split('.')[-1] if '.' in media_name else 'bin'
        filename = f"{file_id}.{ext}"
        filepath = MEDIA_FOLDER / filename
        
        # Save file
        with open(filepath, 'wb') as f:
            f.write(media_bytes)
        
        # Store file info
        file_info = {
            'file_id': file_id,
            'filename': filename,
            'filepath': str(filepath),
            'mime_type': media_type,
            'size': len(media_bytes),
            'uploaded_by': user_email,
            'uploaded_at': datetime.now().isoformat()
        }
        db.media_files[file_id] = file_info
        
        # Create media URL
        media_url = f"/uploads/media/{filename}"
        
        # Add message to database
        media_info = {
            'media_type': media_type,
            'media_url': media_url,
            'media_name': media_name,
            'file_id': file_id,
            'caption': caption
        }
        
        message_data = db.add_message(room_id, user_email, 'media', caption, media_info)
        
        # Broadcast media message
        emit('receive_media', message_data, room=room_id)
        
        logging.info(f"Media sent by {user_email} to room {room_id}: {media_type}")
        
    except Exception as e:
        logging.error(f"Failed to process media: {str(e)}")
        emit('error', {'message': 'Failed to send media'})

@socketio.on('typing')
def handle_typing(data):
    if 'authenticated' not in session:
        return
    
    user_email = session['user_email']
    room_id = data.get('room')
    username = data.get('username')
    
    if room_id and user_email:
        db.typing_users[room_id].add(user_email)
        emit('typing', {
            'room': room_id,
            'email': user_email,
            'username': username
        }, room=room_id, include_self=False)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    if 'authenticated' not in session:
        return
    
    user_email = session['user_email']
    room_id = data.get('room')
    
    if room_id and user_email:
        db.typing_users[room_id].discard(user_email)
        emit('stop_typing', {'room': room_id}, room=room_id, include_self=False)

@socketio.on('create_group')
def handle_create_group(data):
    if 'authenticated' not in session:
        return
    
    group_name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    members = data.get('members', [])
    creator_email = session['user_email']
    
    if not group_name or not members:
        emit('error', {'message': 'Invalid group data'})
        return
    
    # Add creator to members
    if creator_email not in members:
        members.append(creator_email)
    
    # Validate all members exist
    valid_members = []
    for email in members:
        if db.get_user(email):
            valid_members.append(email)
    
    if len(valid_members) < 2:
        emit('error', {'message': 'At least 2 valid members required'})
        return
    
    # Create group
    room_id = generate_room_id()
    group_data = db.create_room(room_id, group_name, 'group', creator_email, valid_members)
    group_data['description'] = description
    
    # Prepare response data
    group_response = {
        'id': room_id,
        'name': group_name,
        'description': description,
        'type': 'group',
        'participants': [db.get_user(email) for email in valid_members],
        'participant_count': len(valid_members),
        'created_by': creator_email,
        'last_message': None,
        'last_activity': group_data['created_at'].isoformat(),
        'unread_count': 0
    }
    
    # Notify all members
    for email in valid_members:
        user_sessions = [sid for sid, user_data in db.active_users.items() if user_data['email'] == email]
        for sid in user_sessions:
            socketio.emit('group_created', {'group': group_response}, room=sid)
    
    logging.info(f"Group created: {group_name} by {creator_email}")

@socketio.on('create_invite')
def handle_create_invite(data):
    if 'authenticated' not in session:
        return
    
    room_id = data.get('room')
    expires_hours = data.get('expires_hours', 24)
    max_uses = data.get('max_uses', 10)
    creator_email = session['user_email']
    
    # Verify user has access to room
    if room_id not in db.user_conversations.get(creator_email, set()):
        emit('error', {'message': 'Access denied'})
        return
    
    # Generate invite
    invite_code = generate_invite_code()
    expires_at = datetime.now() + timedelta(hours=expires_hours) if expires_hours > 0 else None
    
    db.invite_links[invite_code] = {
        'room_id': room_id,
        'created_by': creator_email,
        'created_at': datetime.now(),
        'expires_at': expires_at,
        'max_uses': max_uses,
        'used_count': 0,
        'users_joined': []
    }
    
    invite_url = f"{BASE_URL}/join/{invite_code}"
    
    emit('invite_created', {
        'invite_url': invite_url,
        'invite_code': invite_code,
        'expires_at': expires_at.isoformat() if expires_at else None
    })

@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    if 'authenticated' not in session:
        return
    
    # In a real app, you'd update read receipts in database
    # For now, just acknowledge
    room_id = data.get('room')
    user_email = session['user_email']
    
    logging.info(f"Messages marked as read by {user_email} in room {room_id}")

def broadcast_active_users():
    """Broadcast updated active users list"""
    active_users_list = []
    for session_data in db.active_users.values():
        user_info = {
            'username': session_data['username'],
            'email': session_data['email'],
            'avatar': session_data.get('avatar_url'),
            'last_activity': session_data['last_activity'].isoformat()
        }
        active_users_list.append(user_info)
    
    socketio.emit('active_users', {'users': active_users_list}, broadcast=True)

# Background tasks
def cleanup_expired_data():
    """Clean up expired OTPs, passwords, and invites"""
    now = datetime.now()
    
    # Clean expired OTPs
    expired_otps = [email for email, data in db.otp_storage.items() if now > data['expires']]
    for email in expired_otps:
        del db.otp_storage[email]
    
    # Clean expired dynamic passwords
    expired_passwords = [email for email, data in db.dynamic_passwords.items() if now > data['expires']]
    for email in expired_passwords:
        del db.dynamic_passwords[email]
    
    # Clean expired invites
    expired_invites = [code for code, data in db.invite_links.items() 
                      if data['expires_at'] and now > data['expires_at']]
    for code in expired_invites:
        del db.invite_links[code]

# Run cleanup every 5 minutes
import threading
def background_cleanup():
    while True:
        eventlet.sleep(300)  # 5 minutes
        cleanup_expired_data()

cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
cleanup_thread.start()

@app.route('/join/<invite_code>')
def join_via_invite(invite_code):
    """Handle invite link joins"""
    if invite_code not in db.invite_links:
        flash('Invalid or expired invite link!', 'error')
        return redirect(url_for('login'))
    
    invite_data = db.invite_links[invite_code]
    
    # Check expiry
    if invite_data['expires_at'] and datetime.now() > invite_data['expires_at']:
        del db.invite_links[invite_code]
        flash('This invite link has expired!', 'error')
        return redirect(url_for('login'))
    
    # Check max uses
    if invite_data['used_count'] >= invite_data['max_uses']:
        flash('This invite link has reached its maximum usage!', 'error')
        return redirect(url_for('login'))
    
    # Store invite info in session
    session['pending_invite'] = {
        'code': invite_code,
        'room_id': invite_data['room_id']
    }
    
    room_name = db.rooms.get(invite_data['room_id'], {}).get('name', 'Unknown Room')
    flash(f'Invite accepted! You will join "{room_name}" after login.', 'success')
    return redirect(url_for('login'))

@socketio.on('process_pending_invite')
def process_pending_invite():
    """Process pending invite after user authentication"""
    if 'authenticated' not in session or 'pending_invite' not in session:
        return
    
    user_email = session['user_email']
    invite_info = session['pending_invite']
    invite_code = invite_info['code']
    room_id = invite_info['room_id']
    
    if invite_code in db.invite_links:
        invite_data = db.invite_links[invite_code]
        
        # Check if user already joined via this invite
        if user_email not in invite_data['users_joined']:
            # Add user to room
            db.add_user_to_room(user_email, room_id)
            
            # Update invite usage
            invite_data['used_count'] += 1
            invite_data['users_joined'].append(user_email)
            
            # Join the room
            join_room(room_id)
            db.active_users[request.sid]['rooms'].add(room_id)
            
            # Notify room members
            user_data = db.active_users[request.sid]
            emit('user_joined', {
                'email': user_email,
                'username': user_data['username'],
                'message': f'{user_data["username"]} joined via invite',
                'room': room_id
            }, room=room_id)
            
            # Send success response
            emit('invite_processed', {
                'success': True,
                'room_id': room_id,
                'room_name': db.rooms[room_id]['name']
            })
        
        # Clear pending invite from session
        session.pop('pending_invite', None)

@socketio.on('get_room_members')
def get_room_members(data):
    """Get members of a specific room"""
    if 'authenticated' not in session:
        return
    
    room_id = data.get('room_id')
    user_email = session['user_email']
    
    # Verify access
    if room_id not in db.user_conversations.get(user_email, set()):
        return
    
    if room_id in db.rooms:
        room = db.rooms[room_id]
        members = []
        
        for email in room['participants']:
            user_data = db.get_user(email)
            if user_data:
                # Check if user is currently online
                is_online = any(session_data['email'] == email for session_data in db.active_users.values())
                
                members.append({
                    'email': email,
                    'username': user_data['username'],
                    'avatar_url': user_data.get('avatar_url'),
                    'online': is_online,
                    'last_seen': user_data['last_seen'].isoformat()
                })
        
        emit('room_members', {
            'room_id': room_id,
            'members': members
        })

@socketio.on('search_users')
def search_users(data):
    """Search for users by username or email"""
    if 'authenticated' not in session:
        return
    
    query = data.get('query', '').lower().strip()
    if len(query) < 2:
        emit('search_results', {'users': []})
        return
    
    results = []
    for email, user_data in db.users.items():
        if (query in user_data['username'].lower() or 
            query in user_data['email'].lower()):
            
            # Check if user is online
            is_online = any(session_data['email'] == email for session_data in db.active_users.values())
            
            results.append({
                'email': email,
                'username': user_data['username'],
                'avatar_url': user_data.get('avatar_url'),
                'online': is_online
            })
    
    # Limit results
    results = results[:20]
    emit('search_results', {'users': results})

@socketio.on('start_direct_chat')
def start_direct_chat(data):
    """Start a direct chat with another user"""
    if 'authenticated' not in session:
        return
    
    current_user_email = session['user_email']
    target_email = data.get('target_email')
    
    if not target_email or target_email == current_user_email:
        emit('error', {'message': 'Invalid target user'})
        return
    
    # Check if target user exists
    target_user = db.get_user(target_email)
    if not target_user:
        emit('error', {'message': 'User not found'})
        return
    
    # Check if direct chat already exists
    existing_room = None
    for room_id, room_data in db.rooms.items():
        if (room_data['type'] == 'direct' and 
            set(room_data['participants']) == {current_user_email, target_email}):
            existing_room = room_id
            break
    
    if existing_room:
        # Room already exists, just return it
        emit('direct_chat_ready', {'room_id': existing_room})
    else:
        # Create new direct chat room
        room_id = generate_room_id()
        participants = [current_user_email, target_email]
        
        db.create_room(room_id, f"Chat with {target_user['username']}", 'direct', current_user_email, participants)
        
        emit('direct_chat_ready', {'room_id': room_id})
        
        # Notify target user if online
        target_sessions = [sid for sid, user_data in db.active_users.items() if user_data['email'] == target_email]
        for sid in target_sessions:
            socketio.emit('new_direct_chat', {
                'room_id': room_id,
                'initiator': db.get_user(current_user_email)
            }, room=sid)

@socketio.on('delete_message')
def handle_delete_message(data):
    """Delete a message (for sender only)"""
    if 'authenticated' not in session:
        return
    
    message_id = data.get('message_id')
    room_id = data.get('room_id')
    user_email = session['user_email']
    
    # Find and delete message
    room_messages = db.messages.get(room_id, [])
    for i, msg in enumerate(room_messages):
        if msg['id'] == message_id and msg['sender_email'] == user_email:
            # Mark as deleted instead of removing
            room_messages[i]['content'] = '[Message deleted]'
            room_messages[i]['deleted'] = True
            room_messages[i]['deleted_at'] = datetime.now().isoformat()
            
            # Notify room
            emit('message_deleted', {
                'message_id': message_id,
                'room_id': room_id
            }, room=room_id)
            
            break

@app.route('/api/conversations')
def api_get_conversations():
    """API endpoint to get user conversations"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_email = session['user_email']
    conversations = db.get_user_rooms(user_email)
    
    return jsonify({'conversations': conversations})

@app.route('/api/upload-media', methods=['POST'])
def api_upload_media():
    """API endpoint for media upload"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    file_type = 'image' if file.mimetype.startswith('image/') else 'video'
    
    if not allowed_file(file.filename, file_type):
        return jsonify({'error': 'Invalid file type'}), 400
    
    file_info = save_uploaded_file(file, 'media')
    if file_info:
        media_url = f"/uploads/media/{file_info['filename']}"
        return jsonify({
            'success': True,
            'file_id': file_info['file_id'],
            'media_url': media_url,
            'mime_type': file_info['mime_type']
        })
    
    return jsonify({'error': 'Upload failed'}), 500

@app.route('/api/user-profile', methods=['GET', 'POST'])
def api_user_profile():
    """Get or update user profile"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_email = session['user_email']
    
    if request.method == 'GET':
        user_data = db.get_user(user_email)
        if user_data:
            return jsonify({
                'username': user_data['username'],
                'email': user_data['email'],
                'avatar_url': user_data.get('avatar_url'),
                'created_at': user_data['created_at'].isoformat(),
                'last_seen': user_data['last_seen'].isoformat()
            })
        return jsonify({'error': 'User not found'}), 404
    
    elif request.method == 'POST':
        data = request.get_json()
        new_username = data.get('username', '').strip()
        
        if not new_username:
            return jsonify({'error': 'Username required'}), 400
        
        user_data = db.get_user(user_email)
        if user_data:
            user_data['username'] = new_username
            session['username'] = new_username
            
            # Update active session
            if request.sid in db.active_users:
                db.active_users[request.sid]['username'] = new_username
            
            return jsonify({'success': True, 'username': new_username})
        
        return jsonify({'error': 'User not found'}), 404

# Enhanced template rendering with user data
@app.context_processor
def inject_user_data():
    """Inject user data into all templates"""
    if 'authenticated' in session and session['authenticated']:
        user_email = session['user_email']
        user_data = db.get_user(user_email)
        return {
            'current_user': user_data,
            'user_initials': get_user_initials(user_data['username']) if user_data else 'U'
        }
    return {}

# API Routes for mobile/external access
@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """API login endpoint"""
    data = request.get_json()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    username = data.get('username', '').strip()
    
    if not all([email, password, username]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        validate_email(email)
    except EmailNotValidError:
        return jsonify({'error': 'Invalid email format'}), 400
    
    if password != MASTER_PASSWORD:
        return jsonify({'error': 'Invalid password'}), 401
    
    if is_rate_limited(email):
        return jsonify({'error': 'Rate limited'}), 429
    
    # Generate OTP
    otp = generate_otp()
    db.otp_storage[email] = {
        'otp': otp,
        'expires': datetime.now() + timedelta(minutes=5),
        'attempts': 0
    }
    
    # Add/update user
    db.add_user(email, username)
    
    # Send OTP
    html_body = create_otp_email(otp, username)
    if send_email(email, 'Your CipherChat OTP Code', html_body):
        add_rate_limit(email)
        return jsonify({'success': True, 'message': 'OTP sent'})
    
    return jsonify({'error': 'Failed to send OTP'}), 500

@app.route('/api/rooms/<room_id>/messages')
def api_get_room_messages(room_id):
    """Get messages for a room"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_email = session['user_email']
    
    # Check access
    if room_id not in db.user_conversations.get(user_email, set()):
        return jsonify({'error': 'Access denied'}), 403
    
    messages = db.messages.get(room_id, [])
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    # Paginate messages
    paginated_messages = messages[-(limit + offset):-offset if offset else None]
    
    return jsonify({
        'messages': paginated_messages,
        'total': len(messages),
        'has_more': len(messages) > limit + offset
    })

@app.route('/api/stats')
def api_stats():
    """Get chat statistics"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    stats = {
        'total_users': len(db.users),
        'online_users': len(db.active_users),
        'total_rooms': len(db.rooms),
        'total_messages': sum(len(messages) for messages in db.messages.values()),
        'media_files': len(db.media_files)
    }
    
    return jsonify(stats)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(413)
def file_too_large(error):
    return jsonify({'error': 'File too large'}), 413

# Helper function for templates
def get_user_initials(username):
    """Get user initials"""
    return ''.join(word[0].upper() for word in username.split()[:2])

# Add to template globals
app.jinja_env.globals.update(get_user_initials=get_user_initials)

# Initialize default rooms
def initialize_default_rooms():
    """Create default rooms"""
    if 'general' not in db.rooms:
        db.create_room('general', 'General Chat', 'group', 'system@cipherchat.com')
        logging.info("Created default General Chat room")
    
    if 'announcements' not in db.rooms:
        db.create_room('announcements', 'Announcements', 'group', 'system@cipherchat.com')
        logging.info("Created default Announcements room")

# Resend OTP endpoint
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    if 'email' not in session:
        return jsonify({'success': False, 'message': 'Session expired'})
    
    email = session['email']
    username = session.get('username', 'User')
    
    if is_rate_limited(email):
        return jsonify({'success': False, 'message': 'Too many requests. Please wait.'})
    
    otp = generate_otp()
    db.otp_storage[email] = {
        'otp': otp,
        'expires': datetime.now() + timedelta(minutes=5),
        'attempts': 0
    }
    
    html_body = create_otp_email(otp, username)
    if send_email(email, 'Your CipherChat OTP Code (Resent)', html_body):
        add_rate_limit(email)
        return jsonify({'success': True, 'message': 'OTP resent successfully!'})
    
    return jsonify({'success': False, 'message': 'Failed to send OTP'})

# WebRTC signaling for voice/video calls (basic implementation)
@socketio.on('call_user')
def handle_call_user(data):
    """Handle voice/video call initiation"""
    if 'authenticated' not in session:
        return
    
    caller_email = session['user_email']
    target_email = data.get('target_email')
    call_type = data.get('type', 'voice')  # 'voice' or 'video'
    
    caller_data = db.get_user(caller_email)
    
    # Find target user's session
    target_sessions = [sid for sid, user_data in db.active_users.items() if user_data['email'] == target_email]
    
    for sid in target_sessions:
        socketio.emit('incoming_call', {
            'caller_email': caller_email,
            'caller_username': caller_data['username'],
            'call_type': call_type,
            'caller_avatar': caller_data.get('avatar_url')
        }, room=sid)

@socketio.on('call_response')
def handle_call_response(data):
    """Handle call accept/reject"""
    if 'authenticated' not in session:
        return
    
    caller_email = data.get('caller_email')
    accepted = data.get('accepted', False)
    
    # Find caller's session
    caller_sessions = [sid for sid, user_data in db.active_users.items() if user_data['email'] == caller_email]
    
    for sid in caller_sessions:
        socketio.emit('call_response', {
            'accepted': accepted,
            'responder_email': session['user_email']
        }, room=sid)

# Database persistence (save to JSON files)
def save_data_to_disk():
    """Save critical data to disk"""
    try:
        # Save users
        with open('data/users.json', 'w') as f:
            users_data = {}
            for email, user in db.users.items():
                users_data[email] = {
                    'username': user['username'],
                    'email': user['email'],
                    'avatar_url': user.get('avatar_url'),
                    'created_at': user['created_at'].isoformat(),
                    'last_seen': user['last_seen'].isoformat()
                }
            json.dump(users_data, f, indent=2)
        
        # Save rooms
        with open('data/rooms.json', 'w') as f:
            rooms_data = {}
            for room_id, room in db.rooms.items():
                rooms_data[room_id] = {
                    'id': room['id'],
                    'name': room['name'],
                    'type': room['type'],
                    'participants': room['participants'],
                    'created_by': room['created_by'],
                    'created_at': room['created_at'].isoformat(),
                    'description': room.get('description', '')
                }
            json.dump(rooms_data, f, indent=2)
        
        # Save recent messages (last 100 per room)
        with open('data/messages.json', 'w') as f:
            messages_data = {}
            for room_id, messages in db.messages.items():
                messages_data[room_id] = messages[-100:]  # Keep last 100
            json.dump(messages_data, f, indent=2)
        
        # Save user conversations
        with open('data/user_conversations.json', 'w') as f:
            conv_data = {}
            for email, rooms in db.user_conversations.items():
                conv_data[email] = list(rooms)
            json.dump(conv_data, f, indent=2)
        
        logging.info("Data saved to disk successfully")
        
    except Exception as e:
        logging.error(f"Failed to save data: {str(e)}")

def load_data_from_disk():
    """Load data from disk on startup"""
    try:
        # Create data directory
        os.makedirs('data', exist_ok=True)
        
        # Load users
        try:
            with open('data/users.json', 'r') as f:
                users_data = json.load(f)
                for email, user in users_data.items():
                    db.users[email] = {
                        'username': user['username'],
                        'email': user['email'],
                        'avatar_url': user.get('avatar_url'),
                        'created_at': datetime.fromisoformat(user['created_at']),
                        'last_seen': datetime.fromisoformat(user['last_seen'])
                    }
            logging.info(f"Loaded {len(db.users)} users from disk")
        except FileNotFoundError:
            logging.info("No existing users file found")
        
        # Load rooms
        try:
            with open('data/rooms.json', 'r') as f:
                rooms_data = json.load(f)
                for room_id, room in rooms_data.items():
                    db.rooms[room_id] = {
                        'id': room['id'],
                        'name': room['name'],
                        'type': room['type'],
                        'participants': room['participants'],
                        'created_by': room['created_by'],
                        'created_at': datetime.fromisoformat(room['created_at']),
                        'description': room.get('description', '')
                    }
            logging.info(f"Loaded {len(db.rooms)} rooms from disk")
        except FileNotFoundError:
            logging.info("No existing rooms file found")
        
        # Load messages
        try:
            with open('data/messages.json', 'r') as f:
                messages_data = json.load(f)
                for room_id, messages in messages_data.items():
                    db.messages[room_id] = messages
            logging.info("Loaded messages from disk")
        except FileNotFoundError:
            logging.info("No existing messages file found")
        
        # Load user conversations
        try:
            with open('data/user_conversations.json', 'r') as f:
                conv_data = json.load(f)
                for email, rooms in conv_data.items():
                    db.user_conversations[email] = set(rooms)
            logging.info("Loaded user conversations from disk")
        except FileNotFoundError:
            logging.info("No existing conversations file found")
        
    except Exception as e:
        logging.error(f"Failed to load data: {str(e)}")

# Auto-save data every 5 minutes
def auto_save_data():
    while True:
        eventlet.sleep(300)  # 5 minutes
        save_data_to_disk()

auto_save_thread = threading.Thread(target=auto_save_data, daemon=True)

# Enhanced templates (you'll need to update your template files)
def create_enhanced_chat_template():
    """Template content for enhanced chat.html"""
    return """
{% extends "base.html" %}

{% block title %}CipherChat - Real-time Messaging{% endblock %}

{% block extra_css %}
<style>
    /* Include all the CSS from the HTML artifact above */
</style>
{% endblock %}

{% block content %}
<!-- Include all the HTML content from the artifact above -->
{% endblock %}

{% block extra_js %}
<script>
    // Real user data passed from Flask
    let currentUser = {
        username: '{{ current_user.username if current_user else "Unknown" }}',
        email: '{{ user_email }}',
        avatar: '{{ current_user.avatar_url if current_user and current_user.avatar_url else "" }}'
    };
    
    // Include all the enhanced JavaScript from the artifact above
    // This connects to the real backend endpoints
</script>
{% endblock %}
"""

if __name__ == '__main__':
    print("🔐 Enhanced CipherChat Server Starting...")
    print(f"📧 SMTP configured for: {SMTP_EMAIL}")
    print(f"👤 Admin notifications to: {ADMIN_EMAIL}")
    print("🌐 Server running on: http://localhost:5000")
    print("📁 Upload directories created")
    print("💾 Data persistence enabled")
    print("🔗 Enhanced invite system: ENABLED")
    print("📱 Real-time messaging: ENABLED")
    print("🎥 Media sharing: ENABLED")
    print("👥 Real user management: ENABLED")
    
    # Load existing data
    load_data_from_disk()
    
    # Initialize default rooms
    initialize_default_rooms()
    
    # Start auto-save thread
    import threading
    auto_save_thread.start()
    
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down server...")
        save_data_to_disk()
        print("✅ Data saved successfully")
    except Exception as e:
        print(f"❌ Server error: {str(e)}")
        save_data_to_disk()
        print("✅ Data saved before exit")