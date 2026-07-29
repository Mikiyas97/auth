import re
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt, set_access_cookies, set_refresh_cookies, unset_jwt_cookies
)
from datetime import timedelta
import os
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth as firebase_auth
import secrets
from loginllama import LoginLlama



try:
    cred = credentials.Certificate('firebase-adminsdk.json')
    firebase_admin.initialize_app(cred)
except Exception as e:
    print(f"Firebase Admin SDK initialization failed: {e}")
    print("Please make sure firebase-adminsdk.json is in the root directory.")

app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

load_dotenv()

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]

jwt = JWTManager(app)

loginllama = LoginLlama(api_token=os.environ['LOGINLLAMA_API_KEY'])

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    if jwt_payload.get('type') == 'access':
        return redirect(url_for('refresh', next=request.url))
    else:
        response = redirect(url_for('login'))
        unset_jwt_cookies(response)
        return response

@jwt.unauthorized_loader
def unauthorized_callback(callback):
    return redirect(url_for('login'))

@jwt.invalid_token_loader
def invalid_token_callback(callback):
    response = redirect(url_for('login'))
    unset_jwt_cookies(response)
    return response

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    response = redirect(url_for('login'))
    unset_jwt_cookies(response)
    return response

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    session_id = jwt_payload.get("session_id")
    if not session_id:
        return False
        
    with get_db() as conn:
        cursor = conn.execute("SELECT status FROM sessions WHERE id = ?", (session_id,))
        result = cursor.fetchone()
        is_revoked = result and result[0] == 'Inactive'
        if is_revoked:
            print(f"Token inactive for session {session_id}")
        return is_revoked

DATABASE = "users.db"

PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
)

def risk_score_check(user_email, user_agent, ip_address):
    try:
        result = loginllama.check(
            user_email,
            ip_address=ip_address,
            user_agent=user_agent
        )
        return result.risk_score
    except Exception as e:
        print(f"LoginLlama API error: {e}")
        return None
def get_db():
    return sqlite3.connect(DATABASE)


def create_users_table():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        """)

def create_sessions_table():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                device TEXT,
                location TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'Active'
            )
        """)

def create_session(user_email, device, location):
    create_sessions_table()
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO sessions (user_email, device, location) VALUES (?, ?, ?)",
            (user_email, device, location),
        )
        return cursor.lastrowid

def get_active_sessions(user_email):
    create_sessions_table()
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM sessions WHERE user_email = ? AND status = 'Active'", (user_email,))
        return cursor.fetchall()
        
def revoke_session_in_db(session_id, user_email):
    with get_db() as conn:
        conn.execute("UPDATE sessions SET status = 'Inactive' WHERE id = ? AND user_email = ?", (session_id, user_email))


def create_user(name, email, password):
    create_users_table()
    hashed_password = generate_password_hash(password)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (name, email, hashed_password),
        )


def is_strong_password(password):
    return bool(PASSWORD_PATTERN.match(password))

def get_user_by_email(email):
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cursor.fetchone()

@app.route("/")
def home():
    if not session.get("name"):
        return redirect("/login")

    return render_template("home.html", name=session.get("name"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        user = get_user_by_email(email)
        risk_score = risk_score_check(user_email=email, user_agent=request.user_agent.string, ip_address=request.remote_addr)
        print(f"Risk Score for {email}: {risk_score}")

        
        if user and check_password_hash(user[3], password):

            device = f"{request.user_agent.platform.title() if request.user_agent.platform else 'Unknown OS'} ({request.user_agent.browser.title() if request.user_agent.browser else 'Unknown Browser'})"
            location = request.remote_addr
            session_id = create_session(user[2], device, location)

            access_token = create_access_token(identity=user[2], additional_claims={"session_id": session_id})
            refresh_token = create_refresh_token(identity=user[2], additional_claims={"session_id": session_id})

            print(f"Access Token: {access_token}")
            print(f"Refresh Token: {refresh_token}")

            response = make_response(redirect(url_for("home_page")))
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)

            return response
        return render_template("login.html", error="Invalid email or password.")

    return render_template("login.html")

@app.route("/google-login", methods=["POST"])
@limiter.limit("5 per minute")
def google_login():
    try:
        data = request.get_json()
        token = data.get('token')
        
        decoded_token = firebase_auth.verify_id_token(token, clock_skew_seconds=10)
        email = decoded_token.get('email')
        name = decoded_token.get('name', email.split('@')[0])
        
        user = get_user_by_email(email)
        
        if not user:
            random_password = secrets.token_urlsafe(16) + "aA1!" 
            create_user(name, email, random_password)
            user = get_user_by_email(email)
            
        device = f"{request.user_agent.platform.title() if request.user_agent.platform else 'Unknown OS'} ({request.user_agent.browser.title() if request.user_agent.browser else 'Unknown Browser'})"
        location = request.remote_addr
        session_id = create_session(user[2], device, location)
            
        access_token = create_access_token(identity=user[2], additional_claims={"session_id": session_id})
        refresh_token = create_refresh_token(identity=user[2], additional_claims={"session_id": session_id})

        response = jsonify({"msg": "Google login successful"})
        set_access_cookies(response, access_token)
        set_refresh_cookies(response, refresh_token)
        
        return response
        
    except Exception as e:
        print(f"Google Login Error: {e}")
        return jsonify({"error": "Invalid token or authentication failed"}), 401

@app.route("/logout")
@jwt_required(optional=True)
def logout():
    current_session_id = get_jwt().get("session_id") if get_jwt() else None
    current_user_email = get_jwt_identity()
    
    if current_session_id and current_user_email:
        revoke_session_in_db(current_session_id, current_user_email)

    response = redirect(url_for("login"))
    unset_jwt_cookies(response)
    return response

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not is_strong_password(password):
            return "Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character."

        try:
            create_user(name, email, password)
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            return "Email already exists."

    return render_template("register.html")


@app.route("/home")
@jwt_required()
def home_page():    
    current_user_email = get_jwt_identity()
    name = get_user_by_email(current_user_email)[1] 
    
    current_session_id = get_jwt().get("session_id")
    sessions = get_active_sessions(current_user_email)
    
    return render_template("home.html", name=name, sessions=sessions, current_session_id=current_session_id)




@app.route("/refresh", methods=["GET"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    session_id = get_jwt().get("session_id")

    new_access_token = create_access_token(identity=identity, additional_claims={"session_id": session_id})

    next_url = request.args.get('next', url_for('home_page'))
    response = redirect(next_url)
    set_access_cookies(response, new_access_token)

    return response

if __name__ == "__main__":
    create_users_table()
    create_sessions_table()
    print("db created")
    app.run(debug=True)