import eventlet
eventlet.monkey_patch()
import os
import secrets
import string
import smtplib
import logging
import json
import uuid
import bcrypt
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
import html
import re
import redis
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'e4a7f4f38d5a6c92b1f8b86a9aee79e52e4e0a53c493b6a30a6f2a2c8912bda4')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet", logger=True, engineio_logger=True)

# Initialize Redis for rate limiting and caching
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
redis_client = redis.from_url(redis_url, decode_responses=True)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=redis_url,
    strategy="fixed-window"
)

# Enable CORS
CORS(app)

# Configure rotating file logging
from logging.handlers import RotatingFileHandler

log_handler = RotatingFileHandler(
    "securechat.log",
    maxBytes=10 * 1024 * 1024,  # 10 MB per log file
    backupCount=5               # keep last 5 backups
)

formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
log_handler.setFormatter(formatter)

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(log_handler)

# Optional: also log to console (Render shows these in Dashboard)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
root_logger.addHandler(console_handler)

logging.info("✅ Logging initialized with file rotation and console output")

# Email configuration
SMTP_EMAIL = os.getenv('SMTP_EMAIL', 'gaminghatyar777@gmail.com')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', 'xvjxaszgbseqjwon')
ADMIN_EMAIL = 'spideyofficial777@gmail.com'
MASTER_PASSWORD = os.getenv('MASTER_PASSWORD', 'love123')
BASE_URL = os.getenv('BASE_URL', 'http://localhost:5000')

# In-memory storage (in production, use a proper database)
otp_storage = {}  # {email: {'otp': '123456', 'expires': datetime, 'attempts': 0}}
dynamic_passwords = {}  # {email: {'password': 'abc123', 'expires': datetime}}
rate_limits = defaultdict(list)  # {email: [timestamp1, timestamp2, ...]}
chat_rooms = defaultdict(list)  # {room_name: [messages]}
active_users = {}  # {session_id: {'email': 'user@email.com', 'rooms': [], 'last_active': datetime}}
invite_links = {}  # {invite_code: {'room': 'room_name', 'created_by': 'email', 'expires': datetime, 'max_uses': 5, 'used_count': 0}}
user_profiles = {}  # {email: {'username': 'John Doe', 'avatar': 'base64_data', 'status': 'online', 'last_seen': datetime}}
message_queue = defaultdict(list)  # For offline messages

# Authentication decorator
def authenticated_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session or not session['authenticated']:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# SocketIO authentication
def socket_authenticated_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session or not session['authenticated']:
            disconnect()
        else:
            return f(*args, **kwargs)
    return decorated_function

def is_rate_limited(email, limit=5, period=3600):
    """Check if email is rate limited"""
    now = datetime.now()
    hour_ago = now - timedelta(seconds=period)
    
    # Clean old attempts
    rate_limits[email] = [ts for ts in rate_limits[email] if ts > hour_ago]
    
    return len(rate_limits[email]) >= limit

def add_rate_limit(email):
    """Add rate limit entry for email"""
    rate_limits[email].append(datetime.now())

def generate_otp(length=6):
    """Generate secure OTP"""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def generate_dynamic_password(length=12):
    """Generate secure dynamic password"""
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_invite_code(length=16):
    """Generate secure invite code"""
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    """Check password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def send_email(to_email, subject, html_body):
    """Send HTML email via SMTP with better error handling"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"SecureChat <{SMTP_EMAIL}>"
        msg['To'] = to_email
        
        # Create both HTML and plain text versions
        text_part = MIMEText("Please view this email in an HTML-compatible email client.", 'plain')
        html_part = MIMEText(html_body, 'html')
        
        msg.attach(text_part)
        msg.attach(html_part)
        
        # Try different SMTP configurations
        try:
            # Try SSL first
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(SMTP_EMAIL, SMTP_PASSWORD)
                server.send_message(msg)
                logging.info(f"Email sent via SSL to: {to_email}")
                return True
                
        except Exception as ssl_error:
            logging.warning(f"SSL failed, trying TLS: {ssl_error}")
            
            # Fall back to TLS
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(SMTP_EMAIL, SMTP_PASSWORD)
                server.send_message(msg)
                logging.info(f"Email sent via TLS to: {to_email}")
                return True
                
    except smtplib.SMTPAuthenticationError:
        logging.error("SMTP Authentication failed. Check email credentials.")
        return False
    except smtplib.SMTPRecipientsRefused:
        logging.error(f"Recipient refused: {to_email}")
        return False
    except Exception as e:
        logging.error(f"Email send failed: {str(e)}")
        return False

def create_otp_email(otp):
    """Create HTML email template for OTP"""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Your Secure OTP Code</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
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
                animation: fadeIn 1s ease-in-out;
            }}
            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(15px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
            .logo {{
                font-size: 38px;
                font-weight: 900;
                background: linear-gradient(90deg, #667eea, #764ba2);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 20px;
            }}
            .title {{
                font-size: 26px;
                font-weight: bold;
                color: #222;
                margin-bottom: 12px;
            }}
            .subtitle {{
                font-size: 16px;
                color: #555;
                margin-bottom: 35px;
            }}
            .otp-box {{
                display: inline-block;
                background: linear-gradient(135deg, #00c6ff, #0072ff);
                color: white;
                font-size: 25px;
                font-weight: bold;
                padding: 22px 48px;
                border-radius: 18px;
                letter-spacing: 10px;
                box-shadow: 0 15px 25px rgba(0, 114, 255, 0.4);
                margin-bottom: 25px;
                animation: pulse 2s infinite;
            }}
            @keyframes pulse {{
                0% {{ box-shadow: 0 0 0 0 rgba(0,114,255,0.6); }}
                70% {{ box-shadow: 0 0 0 15px rgba(0,114,255,0); }}
                100% {{ box-shadow: 0 0 0 0 rgba(0,114,255,0); }}
            }}
            .warning {{
                background: #fff8e1;
                border-left: 5px solid #ff9800;
                border-radius: 12px;
                padding: 15px;
                margin: 25px 0;
                font-size: 15px;
                color: #8a6d3b;
            }}
            .expiry {{
                background: #e3f2fd;
                border-left: 5px solid #2196f3;
                border-radius: 12px;
                padding: 15px;
                margin: 20px 0;
                font-size: 15px;
                color: #0d47a1;
            }}
            .security-note {{
                background: #f3e5f5;
                border-left: 5px solid #9c27b0;
                border-radius: 12px;
                padding: 15px;
                margin: 20px 0;
                font-size: 14px;
                color: #4a148c;
            }}
            .footer {{
                margin-top: 35px;
                font-size: 13px;
                color: #777;
                line-height: 1.6;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <div class="logo">🔐 SecureChat</div>
                <div class="title">Your One-Time Password</div>
                <div class="subtitle">Please use the following OTP to verify your identity:</div>
                
                <div class="otp-box">{otp}</div>
                
                <div class="warning">
                    ⚠️ <strong>Important Security Notice:</strong><br>
                    Never share your OTP with anyone. Our team will never ask you for this code.
                </div>
                
                <div class="expiry">
                    ⏰ <strong>Validity:</strong> This OTP will expire in <strong>5 minutes</strong>.
                </div>
                
                <div class="security-note">
                    🛡️ This is an automated security message from <strong>SecureChat</strong>.<br>
                    If you did not request this code, you can safely ignore this email.
                </div>
                
                <div class="footer">
                    <p>🔒 SecureChat - Your Privacy, Our Priority</p>
                    <p>© 2025 SecureChat. All Rights Reserved.</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

def create_invite_email(invite_url, room_name, created_by, expires_in="24 hours"):
    """Create HTML email for invite links"""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SecureChat Invitation</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .email-card {{ background: rgba(255, 255, 255, 0.95); border-radius: 20px; padding: 40px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); backdrop-filter: blur(10px); }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .logo {{ font-size: 32px; font-weight: bold; color: #667eea; margin-bottom: 10px; }}
            .title {{ font-size: 24px; color: #333; margin-bottom: 10px; }}
            .subtitle {{ color: #666; font-size: 16px; }}
            .invite-container {{ text-align: center; margin: 30px 0; }}
            .invite-btn {{ display: inline-block; background: linear-gradient(135deg, #4CAF50, #45a049); color: white; font-size: 18px; font-weight: bold; padding: 15px 30px; border-radius: 50px; text-decoration: none; box-shadow: 0 10px 20px rgba(76, 175, 80, 0.3); transition: transform 0.2s; }}
            .invite-btn:hover {{ transform: translateY(-2px); }}
            .invite-link {{ background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 15px; margin: 20px 0; word-break: break-all; font-family: monospace; }}
            .info-box {{ background: #e7f3ff; border-radius: 8px; padding: 15px; margin: 20px 0; }}
            .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 14px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="email-card">
                <div class="header">
                    <div class="logo">🔐 SecureChat</div>
                    <h1 class="title">You're Invited!</h1>
                    <p class="subtitle">Join the conversation on SecureChat</p>
                </div>
                
                <div class="invite-container">
                    <a href="{invite_url}" class="invite-btn">Join Chat Room</a>
                </div>
                
                <div class="invite-link">
                    <strong>Or copy this link:</strong><br>
                    {invite_url}
                </div>
                
                <div class="info-box">
                    <strong>📋 Invitation Details:</strong><br>
                    • <strong>Room:</strong> {room_name}<br>
                    • <strong>Invited by:</strong> {created_by}<br>
                    • <strong>Expires:</strong> {expires_in}<br>
                    • <strong>Security:</strong> End-to-end encrypted
                </div>
                
                <div class="warning" style="background: #fff3cd; border-radius: 8px; padding: 15px; margin: 20px 0; text-align: center;">
                    <span style="font-size: 20px; margin-right: 10px;">⚠️</span>
                    <strong>Only share with trusted people!</strong><br>
                    This link provides access to the chat room.
                </div>
                
                <div class="footer">
                    <p>SecureChat - Your Privacy, Our Priority</p>
                    <p>© 2025 SecureChat. All rights reserved.</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

def create_admin_notification_email(user_email, login_time, user_info):
    """Create admin notification email"""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>New User Login - SecureChat</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }}
            .container {{ max-width: 700px; margin: 0 auto; padding: 20px; }}
            .email-card {{ background: white; border-radius: 15px; padding: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }}
            .header {{ text-align: center; margin-bottom: 30px; border-bottom: 2px solid #667eea; padding-bottom: 20px; }}
            .title {{ color: #667eea; font-size: 28px; margin-bottom: 10px; }}
            .alert {{ background: #d4edda; border: 1px solid #c3e6cb; border-radius: 8px; padding: 15px; margin: 20px 0; color: #155724; }}
            .info-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            .info-table th, .info-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            .info-table th {{ background: #f8f9fa; font-weight: bold; color: #495057; }}
            .timestamp {{ background: #fff3cd; border-radius: 5px; padding: 8px; font-family: monospace; }}
            .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 14; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="email-card">
                <div class="header">
                    <h1 class="title">🔔 New User Login Alert</h1>
                    <p>SecureChat Admin Notification</p>
                </div>
                
                <div class="alert">
                    <strong>✅ Successful Authentication</strong><br>
                    A user has successfully completed the full authentication process.
                </div>
                
                <table class="info-table">
                    <tr>
                        <th>👤 User Email</th>
                        <td>{user_email}</td>
                    </tr>
                    <tr>
                        <th>🕐 Login Time</th>
                        <td><span class="timestamp">{login_time}</span></td>
                    </tr>
                    <tr>
                        <th>🌐 IP Address</th>
                        <td>{user_info.get('ip', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <th>🖥️ User Agent</th>
                        <td>{user_info.get('user_agent', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <th>🔐 Authentication Steps</th>
                        <td>✅ Master Password → ✅ OTP Verification → ✅ Dynamic Password</td>
                    </tr>
                    <tr>
                        <th>🛡️ Security Level</th>
                        <td><strong style="color: #28a745;">HIGH - 3-Factor Authentication</strong></td>
                    </tr>
                </table>
                
                <div class="footer">
                    <p><strong>SecureChat Admin Panel</strong></p>
                    <p>This is an automated security notification</p>
                    <p>© 2025 SecureChat. All rights reserved.</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

def create_user_notification_email(user_email, login_time, user_info):
    """Create user login notification email"""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login Successful</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0; padding: 0;
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: #333;
            }}
            .container {{
                max-width: 650px; margin: 0 auto; padding: 30px 20px;
            }}
            .card {{
                background: rgba(255, 255, 255, 0.97);
                border-radius: 25px;
                padding: 45px;
                box-shadow: 0 25px 50px rgba(0,0,0,0.15);
                backdrop-filter: blur(12px);
                text-align: center;
                animation: fadeIn 1.2s ease-in-out;
            }}
            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(20px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
            .logo {{
                font-size: 42px;
                font-weight: 900;
                background: linear-gradient(90deg, #667eea, #764ba2);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 20px;
            }}
            .title {{
                font-size: 26px; font-weight: bold; margin-bottom: 15px;
            }}
            .details {{
                text-align: left; margin-top: 20px;
                background: #f9f9f9; border-radius: 15px;
                padding: 20px; font-size: 15px; color: #444;
                box-shadow: inset 0 2px 8px rgba(0,0,0,0.05);
            }}
            .highlight {{
                color: #0072ff; font-weight: bold;
            }}
            .button {{
                display: inline-block;
                margin-top: 25px;
                padding: 14px 28px;
                background: linear-gradient(135deg, #00c6ff, #0072ff);
                color: white; text-decoration: none;
                border-radius: 12px; font-weight: bold;
                box-shadow: 0 10px 20px rgba(0,114,255,0.4);
                transition: transform 0.2s;
            }}
            .button:hover {{
                transform: scale(1.05);
            }}
            .footer {{
                margin-top: 30px;
                font-size: 13px; color: #777; line-height: 1.6;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <div class="logo">🔐 SecureChat</div>
                <div class="title">Login Successful 🎉</div>
                <p>Hello <strong>{user_email}</strong>,<br>
                You have successfully logged in to <strong>SecureChat</strong>.</p>
                
                <div class="details">
                    <p><strong>📅 Login Time:</strong> {login_time}</p>
                    <p><strong>🌍 IP Address:</strong> {user_info['ip']}</p>
                    <p><strong>💻 Device:</strong> {user_info['user_agent']}</p>
                </div>
                
                <a href="{BASE_URL}/chat" target="_blank" class="button">Start Chatting 🚀</a>
                
                <div class="footer">
                    <p>🔒 SecureChat - Your Privacy, Our Priority</p>
                    <p>© 2025 SecureChat. All Rights Reserved.</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

def sanitize_message(message):
    """Sanitize message to prevent XSS"""
    # Escape HTML
    message = html.escape(message)
    # Remove any script tags
    message = re.sub(r'<script.*?</script>', '', message, flags=re.IGNORECASE | re.DOTALL)
    return message.strip()

def cleanup_expired_invites():
    """Clean up expired invite links"""
    now = datetime.now()
    expired_keys = []
    for code, invite_data in invite_links.items():
        if now > invite_data['expires']:
            expired_keys.append(code)
    
    for code in expired_keys:
        del invite_links[code]

def store_offline_message(recipient_email, message_data):
    """Store message for offline delivery"""
    if recipient_email not in message_queue:
        message_queue[recipient_email] = []
    
    message_queue[recipient_email].append({
        **message_data,
        'stored_at': datetime.now().isoformat()
    })
    
    # Store in Redis for persistence (15 days expiration)
    redis_key = f"offline_msg:{recipient_email}"
    redis_client.setex(redis_key, 15*24*3600, json.dumps(message_queue[recipient_email]))

def get_offline_messages(recipient_email):
    """Retrieve offline messages for a user"""
    redis_key = f"offline_msg:{recipient_email}"
    messages = redis_client.get(redis_key)
    
    if messages:
        return json.loads(messages)
    return []

def clear_offline_messages(recipient_email):
    """Clear offline messages for a user"""
    redis_key = f"offline_msg:{recipient_email}"
    redis_client.delete(redis_key)
    if recipient_email in message_queue:
        del message_queue[recipient_email]

@app.route('/')
def index():
    if 'authenticated' in session and session['authenticated']:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        # Log attempt
        logging.info(f"Login attempt for email: {email}")
        
        # Validate email format
        try:
            validate_email(email)
        except EmailNotValidError:
            flash('❌ Invalid email format!', 'error')
            logging.warning(f"Invalid email format: {email}")
            return render_template('login.html')
        
        # Check master password
        if not check_password(password, hash_password(MASTER_PASSWORD)):
            flash('❌ Invalid master password!', 'error')
            logging.warning(f"Invalid master password for: {email}")
            return render_template('login.html')
        
        # Check rate limiting
        if is_rate_limited(email):
            flash('❌ Too many OTP requests. Please try again later.', 'error')
            logging.warning(f"Rate limited: {email}")
            return render_template('login.html')
        
        # Generate and store OTP
        otp = generate_otp()
        otp_storage[email] = {
            'otp': otp,
            'expires': datetime.now() + timedelta(minutes=5),
            'attempts': 0
        }
        
        # Send OTP email
        html_body = create_otp_email(otp)
        if send_email(email, '🔐 Your SecureChat OTP Code', html_body):
            add_rate_limit(email)
            session['email'] = email
            session['otp_sent'] = True
            flash('✅ OTP sent to your email!', 'success')
            logging.info(f"OTP sent successfully to: {email}")
            return redirect(url_for('verify_otp'))
        else:
            flash('❌ Failed to send OTP. Please try again.', 'error')
            logging.error(f"Failed to send OTP to: {email}")
    
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def verify_otp():
    if 'email' not in session or 'otp_sent' not in session:
        return redirect(url_for('login'))
    
    email = session['email']
    
    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        
        # Check if OTP exists and not expired
        if email not in otp_storage:
            flash('❌ OTP expired. Please login again.', 'error')
            return redirect(url_for('login'))
        
        otp_data = otp_storage[email]
        
        if datetime.now() > otp_data['expires']:
            del otp_storage[email]
            flash('❌ OTP expired. Please login again.', 'error')
            logging.warning(f"OTP expired for: {email}")
            return redirect(url_for('login'))
        
        # Check OTP attempts
        if otp_data['attempts'] >= 3:
            del otp_storage[email]
            flash('❌ Too many failed attempts. Please login again.', 'error')
            logging.warning(f"Too many OTP attempts for: {email}")
            return redirect(url_for('login'))
        
        # Verify OTP
        if entered_otp == otp_data['otp']:
            # OTP correct, generate dynamic password
            dynamic_pass = generate_dynamic_password()
            dynamic_passwords[email] = {
                'password': dynamic_pass,
                'expires': datetime.now() + timedelta(minutes=5)
            }
            
            # Clean up OTP
            del otp_storage[email]
            
            session['otp_verified'] = True
            session['dynamic_password'] = dynamic_pass
            flash('✅ OTP verified! Here is your dynamic password.', 'success')
            logging.info(f"OTP verified successfully for: {email}")
            return redirect(url_for('dynamic_verify'))
        else:
            otp_data['attempts'] += 1
            flash('❌ Invalid OTP. Please try again.', 'error')
            logging.warning(f"Invalid OTP attempt for: {email}")
    
    return render_template('verify_otp.html')

@app.route('/resend-otp', methods=['POST'])
@limiter.limit("3 per hour")
def resend_otp():
    if 'email' not in session:
        return jsonify({'success': False, 'message': 'Session expired'})
    
    email = session['email']
    
    # Check rate limiting
    if is_rate_limited(email):
        return jsonify({'success': False, 'message': 'Too many requests. Please wait.'})
    
    # Generate new OTP
    otp = generate_otp()
    otp_storage[email] = {
        'otp': otp,
        'expires': datetime.now() + timedelta(minutes=5),
        'attempts': 0
    }
    
    # Send OTP email
    html_body = create_otp_email(otp)
    if send_email(email, '🔐 Your SecureChat OTP Code (Resent)', html_body):
        add_rate_limit(email)
        logging.info(f"OTP resent to: {email}")
        return jsonify({'success': True, 'message': 'OTP resent successfully!'})
    else:
        logging.error(f"Failed to resend OTP to: {email}")
        return jsonify({'success': False, 'message': 'Failed to send OTP'})

@app.route('/dynamic-verify', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def dynamic_verify():
    if 'email' not in session or 'otp_verified' not in session:
        return redirect(url_for('login'))
    
    email = session['email']
    
    if request.method == 'POST':
        entered_password = request.form.get('dynamic_password', '').strip()
        
        # Check if dynamic password exists and not expired
        if email not in dynamic_passwords:
            flash('❌ Dynamic password expired. Please login again.', 'error')
            return redirect(url_for('login'))
        
        pass_data = dynamic_passwords[email]
        
        if datetime.now() > pass_data['expires']:
            del dynamic_passwords[email]
            flash('❌ Dynamic password expired. Please login again.', 'error')
            logging.warning(f"Dynamic password expired for: {email}")
            return redirect(url_for('login'))
        
        # Verify dynamic password
        if entered_password == pass_data['password']:
            # Authentication complete!
            del dynamic_passwords[email]
            
            session['authenticated'] = True
            session['user_email'] = email
            session['user_id'] = str(uuid.uuid4())
            
            # Initialize user profile if not exists
            if email not in user_profiles:
                user_profiles[email] = {
                    'username': email.split('@')[0].title(),
                    'avatar': None,
                    'status': 'online',
                    'last_seen': datetime.now().isoformat(),
                    'created_at': datetime.now().isoformat()
                }
            
            # Collect user info
            user_info = {
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', 'Unknown')
            }
            
            # Send admin notification
            admin_html = create_admin_notification_email(
                email, 
                datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                user_info
            )
            send_email(ADMIN_EMAIL, f'🔔 New Login: {email}', admin_html)
            
            # Send user notification
            user_html = create_user_notification_email(
                email, 
                datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                user_info
            )
            send_email(email, "✅ Login Successful - SecureChat", user_html)
            
            flash('🔐 Authentication successful! Welcome to SecureChat.', 'success')
            logging.info(f"Full authentication completed for: {email}")
            return redirect(url_for('chat'))
        else:
            flash('❌ Invalid dynamic password!', 'error')
            logging.warning(f"Invalid dynamic password for: {email}")
    
    return render_template('dynamic_verify.html')

@app.route('/chat')
@authenticated_only
def chat():
    user_email = session['user_email']
    
    # Update user status
    if user_email in user_profiles:
        user_profiles[user_email]['status'] = 'online'
        user_profiles[user_email]['last_seen'] = datetime.now().isoformat()
    
    return render_template('chat.html', 
                         user_email=user_email, 
                         username=user_profiles.get(user_email, {}).get('username', user_email))

@app.route('/create-invite', methods=['POST'])
@authenticated_only
def create_invite():
    data = request.get_json()
    room_name = data.get('room', 'general')
    max_uses = data.get('max_uses', 5)
    expires_hours = data.get('expires_hours', 24)
    
    # Generate invite code
    invite_code = generate_invite_code()
    
    # Store invite data
    invite_links[invite_code] = {
        'room': room_name,
        'created_by': session['user_email'],
        'created_at': datetime.now(),
        'expires': datetime.now() + timedelta(hours=expires_hours),
        'max_uses': max_uses,
        'used_count': 0,
        'users': []
    }
    
    # Create invite URL
    invite_url = f"{BASE_URL}/join/{invite_code}"
    
    return jsonify({
        'success': True,
        'invite_url': invite_url,
        'invite_code': invite_code,
        'expires': invite_links[invite_code]['expires'].isoformat()
    })

@app.route('/join/<invite_code>')
def join_via_invite(invite_code):
    # Clean up expired invites first
    cleanup_expired_invites()
    
    if invite_code not in invite_links:
        flash('❌ Invalid or expired invite link!', 'error')
        return redirect(url_for('login'))
    
    invite_data = invite_links[invite_code]
    
    # Check if invite is expired
    if datetime.now() > invite_data['expires']:
        del invite_links[invite_code]
        flash('❌ This invite link has expired!', 'error')
        return redirect(url_for('login'))
    
    # Check if max uses reached
    if invite_data['used_count'] >= invite_data['max_uses']:
        flash('❌ This invite link has reached its maximum usage!', 'error')
        return redirect(url_for('login'))
    
    # Store invite data in session for after login
    session['invite_code'] = invite_code
    session['invite_room'] = invite_data['room']
    
    flash(f'✅ Invite accepted! You will join "{invite_data["room"]}" after login.', 'success')
    return redirect(url_for('login'))

@app.route('/get-invites')
@authenticated_only
def get_invites():
    user_email = session['user_email']
    user_invites = {}
    
    for code, data in invite_links.items():
        if data['created_by'] == user_email:
            user_invites[code] = {
                'room': data['room'],
                'created_at': data['created_at'].isoformat(),
                'expires': data['expires'].isoformat(),
                'max_uses': data['max_uses'],
                'used_count': data['used_count'],
                'invite_url': f"{BASE_URL}/join/{code}"
            }
    
    return jsonify({'success': True, 'invites': user_invites})

@app.route('/revoke-invite/<invite_code>', methods=['POST'])
@authenticated_only
def revoke_invite(invite_code):
    if invite_code in invite_links:
        if invite_links[invite_code]['created_by'] == session['user_email']:
            del invite_links[invite_code]
            return jsonify({'success': True, 'message': 'Invite revoked'})
    
    return jsonify({'success': False, 'message': 'Invite not found'})

@app.route('/profile/update', methods=['POST'])
@authenticated_only
def update_profile():
    user_email = session['user_email']
    data = request.get_json()
    
    if user_email not in user_profiles:
        user_profiles[user_email] = {}
    
    if 'username' in data:
        user_profiles[user_email]['username'] = data['username'][:50]  # Limit length
    
    if 'status' in data and data['status'] in ['online', 'away', 'busy', 'offline']:
        user_profiles[user_email]['status'] = data['status']
    
    if 'avatar' in data:
        # Basic validation for avatar data (in real app, would do more validation)
        if data['avatar'].startswith('data:image/'):
            user_profiles[user_email]['avatar'] = data['avatar']
    
    return jsonify({'success': True, 'profile': user_profiles[user_email]})

@app.route('/profile/<email>')
@authenticated_only
def get_profile(email):
    if email in user_profiles:
        profile_data = user_profiles[email].copy()
        # Don't expose sensitive information
        if 'email' in profile_data:
            del profile_data['email']
        return jsonify({'success': True, 'profile': profile_data})
    
    return jsonify({'success': False, 'message': 'Profile not found'})

@app.route('/logout')
def logout():
    email = session.get('user_email')
    if email:
        # Update user status
        if email in user_profiles:
            user_profiles[email]['status'] = 'offline'
            user_profiles[email]['last_seen'] = datetime.now().isoformat()
        
        logging.info(f"User logged out: {email}")
    
    session.clear()
    flash('✅ Logged out successfully!', 'success')
    return redirect(url_for('login'))

# SocketIO Events
@socketio.on('connect')
def on_connect():
    if 'authenticated' not in session or not session['authenticated']:
        return False
    
    user_email = session['user_email']
    user_id = session.get('user_id', str(uuid.uuid4()))
    
    active_users[request.sid] = {
        'email': user_email,
        'user_id': user_id,
        'rooms': ['general'],
        'last_active': datetime.now()
    }
    
    # Update user status
    if user_email in user_profiles:
        user_profiles[user_email]['status'] = 'online'
        user_profiles[user_email]['last_seen'] = datetime.now().isoformat()
    
    # Check if user joined via invite
    if 'invite_code' in session and 'invite_room' in session:
        room_name = session['invite_room']
        invite_code = session['invite_code']
        
        if invite_code in invite_links:
            invite_data = invite_links[invite_code]
            
            # Check if user already used this invite
            if user_email not in invite_data['users']:
                join_room(room_name)
                active_users[request.sid]['rooms'].append(room_name)
                
                # Update invite usage
                invite_data['used_count'] += 1
                invite_data['users'].append(user_email)
                
                # Remove invite data from session
                session.pop('invite_code', None)
                session.pop('invite_room', None)
                
                # Notify room
                emit('user_joined', {
                    'email': user_email,
                    'username': user_profiles.get(user_email, {}).get('username', user_email),
                    'message': f'{user_email} joined via invite link',
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                }, room=room_name)
            else:
                # User already used this invite, join general
                join_room('general')
        else:
            # Invite expired or invalid, join general
            join_room('general')
    else:
        # Regular login, join general room
        join_room('general')
    
    # Send active users list
    users_list = []
    for user_data in active_users.values():
        email = user_data['email']
        if email in user_profiles:
            users_list.append({
                'email': email,
                'username': user_profiles[email].get('username', email),
                'status': user_profiles[email].get('status', 'online'),
                'last_seen': user_profiles[email].get('last_seen')
            })
    
    emit('active_users', {'users': users_list}, room='general')
    
    # Deliver any offline messages
    offline_msgs = get_offline_messages(user_email)
    if offline_msgs:
        emit('offline_messages', {'messages': offline_msgs})
        clear_offline_messages(user_email)
        logging.info(f"Delivered {len(offline_msgs)} offline messages to {user_email}")

@socketio.on('disconnect')
def on_disconnect():
    if request.sid in active_users:
        user_data = active_users[request.sid]
        user_email = user_data['email']
        
        for room in user_data['rooms']:
            leave_room(room)
            emit('user_left', {
                'email': user_email,
                'username': user_profiles.get(user_email, {}).get('username', user_email),
                'message': f'{user_email} left the chat',
                'timestamp': datetime.now().strftime('%H:%M:%S')
            }, room=room)
        
        # Update user status
        if user_email in user_profiles:
            user_profiles[user_email]['status'] = 'offline'
            user_profiles[user_email]['last_seen'] = datetime.now().isoformat()
        
        del active_users[request.sid]
        
        # Update active users list
        users_list = []
        for user_data in active_users.values():
            email = user_data['email']
            if email in user_profiles:
                users_list.append({
                    'email': email,
                    'username': user_profiles[email].get('username', email),
                    'status': user_profiles[email].get('status', 'online'),
                    'last_seen': user_profiles[email].get('last_seen')
                })
        
        emit('active_users', {'users': users_list}, broadcast=True)

@socketio.on('send_message')
def handle_message(data):
    if 'authenticated' not in session or not session['authenticated']:
        return
    
    user_email = session['user_email']
    room = data.get('room', 'general')
    message = sanitize_message(data.get('message', ''))
    
    if not message.strip():
        return
    
    message_data = {
        'id': str(uuid.uuid4()),
        'email': user_email,
        'username': user_profiles.get(user_email, {}).get('username', user_email),
        'message': message,
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'room': room
    }
    
    # Check for media content
    if 'media_type' in data and 'media_data' in data:
        message_data['media_type'] = data['media_type']
        message_data['media_data'] = data['media_data']
        if 'media_name' in data:
            message_data['media_name'] = data['media_name']
    
    # Store message (keep last 100 per room)
    chat_rooms[room].append(message_data)
    if len(chat_rooms[room]) > 100:
        chat_rooms[room] = chat_rooms[room][-100:]
    
    # Check if recipient is online
    recipient_online = False
    for sid, user_data in active_users.items():
        if user_data['email'] != user_email and room in user_data['rooms']:
            recipient_online = True
            break
    
    if recipient_online:
        emit('receive_message', message_data, room=room)
    else:
        # Store for offline delivery
        store_offline_message(room, message_data)
    
    # Update user's last active time
    if request.sid in active_users:
        active_users[request.sid]['last_active'] = datetime.now()

@socketio.on('join_room')
def on_join_room(data):
    if 'authenticated' not in session or not session['authenticated']:
        return
    
    user_email = session['user_email']
    room = data['room']
    
    join_room(room)
    
    if request.sid in active_users:
        active_users[request.sid]['rooms'].append(room)
        active_users[request.sid]['last_active'] = datetime.now()
    
    # Send recent messages for this room
    recent_messages = chat_rooms.get(room, [])[-50:]  # Last 50 messages
    emit('room_history', {'messages': recent_messages})
    
    emit('user_joined', {
        'email': user_email,
        'username': user_profiles.get(user_email, {}).get('username', user_email),
        'message': f'{user_email} joined {room}',
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }, room=room)

@socketio.on('leave_room')
def on_leave_room(data):
    if 'authenticated' not in session or not session['authenticated']:
        return
    
    user_email = session['user_email']
    room = data['room']
    
    leave_room(room)
    
    if request.sid in active_users and room in active_users[request.sid]['rooms']:
        active_users[request.sid]['rooms'].remove(room)
        active_users[request.sid]['last_active'] = datetime.now()
    
    emit('user_left', {
        'email': user_email,
        'username': user_profiles.get(user_email, {}).get('username', user_email),
        'message': f'{user_email} left {room}',
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }, room=room)

@socketio.on('typing')
def on_typing(data):
    if 'authenticated' not in session or not session['authenticated']:
        return
    
    user_email = session['user_email']
    room = data.get('room')
    
    if room:
        emit('typing', {
            'email': user_email,
            'username': user_profiles.get(user_email, {}).get('username', user_email),
            'room': room
        }, room=room, include_self=False)

@socketio.on('stop_typing')
def on_stop_typing(data):
    if 'authenticated' not in session or not session['authenticated']:
        return
    
    user_email = session['user_email']
    room = data.get('room')
    
    if room:
        emit('stop_typing', {
            'email': user_email,
            'room': room
        }, room=room, include_self=False)

@socketio.on('message_read')
def on_message_read(data):
    if 'authenticated' not in session or not session['authenticated']:
        return
    
    message_id = data.get('message_id')
    room = data.get('room')
    
    if message_id and room:
        # Find the message and update its status
        for msg in chat_rooms.get(room, []):
            if msg.get('id') == message_id:
                msg['status'] = 'read'
                # Notify the sender if they're in the same room
                emit('message_status', {
                    'message_id': message_id,
                    'status': 'read',
                    'read_by': session['user_email']
                }, room=room)
                break

if __name__ == '__main__':
    print("🔐 SecureChat Server Starting...")
    print("📧 SMTP configured for:", SMTP_EMAIL)
    print("👤 Admin notifications to:", ADMIN_EMAIL)
    print("🌐 Server running on: http://localhost:5000")
    print("🔗 Invite link system: ENABLED")
    print("📊 Redis caching: ENABLED")
    print("⚡ Socket.IO: ENABLED")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)