# Secure Authentication System

A full-stack identity and authentication system built with **Flask (Python)** on the backend and **JavaScript** on the frontend. The system enables users to securely create accounts, sign in, maintain sessions, and access protected resources 

---

## Project Overview

This project implements a complete authentication system.

- **Register** with a strong password (validated on both client and server sides)
- **Log in** with email/password or via **Google OAuth**
- **Stay logged in** using short-lived JWT access tokens that silently refresh via long-lived refresh tokens
- Be **protected from brute-force attacks** through rate limiting
- Be **monitored for suspicious login activity** using the LoginLlama risk-scoring API
- **View and manage all their active sessions** from the home dashboard

---

## Technology Stack

| Layer         | Technology                         | Purpose                                      |
|---------------|------------------------------------|----------------------------------------------|
| **Backend**   | Flask (Python)                     | Web framework, routing, and server logic     |
| **Database**  | SQLite                             | Lightweight storage for users and sessions   |
| **Auth Tokens** | Flask-JWT-Extended               | JWT-based access and refresh token management|
| **Password Hashing** | Werkzeug Security             | Bcrypt-based password hashing                |
| **Rate Limiting** | Flask-Limiter                  | Brute-force protection via request throttling|
| **OAuth Provider** | Firebase Authentication (Google) | Google Sign-In via popup flow               |
| **Risk Detection** | LoginLlama API                | Suspicious login activity risk scoring       |
| **Frontend**  | HTML, CSS, JavaScript              | UI, forms, client-side validation            |
| **Environment** | python-dotenv                    | Secure management of secrets via `.env`      |

---

## Project Structure

```
auth/
├── app.py                        # Main Flask application (all backend logic)
├── requirements.txt              # Python dependencies
├── .env                          # Environment variables (JWT secret, API keys)
├── .gitignore                    # Git ignore rules (protects secrets & DB)
├── firebase-adminsdk.json        # Firebase Admin SDK credentials (server-side)
├── users.db                      # SQLite database (auto-created)
│
├── static/
│   ├── style.css                 # Global stylesheet
│   └── js/
│       ├── firebase-config.js    # Firebase client-side initialization
│       ├── google-auth.js        # Google Sign-In popup flow handler
│       ├── login.js              # Login form submission handler
│       └── register.js           # Registration form + password validation
│
└── templates/
    ├── login.html                # Login page (email/password + Google)
    ├── register.html             # Registration page with password rules + Google
    └── home.html                 # Dashboard with session management
```

---

## Security Requirements & Implementation

### 1. Weak Password Prevention

> **Requirement:** *"Users must not be able to use weak passwords."*

**Implementation:** Dual-layer validation on both the client side and the server side ensures that no weak password can slip through.

#### Server-Side Validation (`app.py`)

A regex pattern enforces the following rules before any password is accepted:

```python
PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
)
```

The `register()` route calls `is_strong_password()` before creating the user. If the password is weak, registration is rejected with a descriptive error message.

| Rule                          | Enforced By       |
|-------------------------------|-------------------|
| Minimum 8 characters          | Regex `{8,}`      |
| At least 1 uppercase letter   | `(?=.*[A-Z])`     |
| At least 1 lowercase letter   | `(?=.*[a-z])`     |
| At least 1 digit              | `(?=.*\d)`        |
| At least 1 special character  | `(?=.*[@$!%*?&])` |

#### Client-Side Validation (`register.js`)

The same regex pattern is mirrored in JavaScript to give instant feedback:

```javascript
let regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@.#$!%*?&])[A-Za-z\d@.#$!%*?&]{8,15}$/;
```

The form also confirms passwords match before submission. If validation fails, a message ("weak password" or "Passwords do not match") is shown to the user and the form is not submitted.

#### Password Storage

Passwords are never stored in plain text. They are hashed using Werkzeug's `generate_password_hash()` (which is a one way encryption algorithm) fore being stored in the database.

---

### 2. Brute-Force Attack Protection

> **Requirement:** *"The system must prevent brute-force login attacks."*

**Implementation:** Flask-Limiter applies rate limiting to the login endpoints.

```python
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    ...

@app.route("/google-login", methods=["POST"])
@limiter.limit("5 per minute")
def google_login():
    ...
```

| Protection Layer        | Configuration              |
|------------------------|----------------------------|
| **Login endpoint**     | 5 requests per minute per IP |
| **Google login endpoint** | 5 requests per minute per IP |
| **Global default**     | 200 requests/day, 50/hour  |

An attacker trying to guess passwords via automated scripts will be blocked after 5 attempts within a single minute. The rate limit is applied per IP address using `get_remote_address`, which means each client is individually identified.

---

### 3. Persistent Login Without Long-Lived Access Tokens

> **Requirement:** *"Users should stay logged in without keeping long-lived access tokens."*

**Implementation:** A **short-lived access token + long-lived refresh token** strategy using JWT cookies.

```python
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15    # Short-lived
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)     # Long-lived
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]                   # HTTP-only cookies
```

#### How the Token Refresh Flow Works

```
User Logs In
    │
    ├── Access Token issued  (expires in 15 minute)
    └── Refresh Token issued (expires in 30 days)
           │
           ▼
    User Makes a Request
           │
    ┌──────┴──────┐
    │ Access Token │
    │   Expired?   │
    └──────┬──────┘
      No   │   Yes
       │   │    │
       ▼   │    ▼
    Allow   │  Redirect to /refresh
    Access  │    │
            │    ▼
            │  Refresh token is validated
            │    │
            │    ▼
            │  New Access Token is issued
            │    │
            │    ▼
            └──► User is seamlessly redirected back
```

The `expired_token_callback` in `app.py` handles the seamless refresh:

```python
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    if jwt_payload.get('type') == 'access':
        return redirect(url_for('refresh', next=request.url))
    else:
        response = redirect(url_for('login'))
        unset_jwt_cookies(response)
        return response
```

**Key Security Benefit:** Even if an access token is intercepted, the attacker only has a 15-minute window. The long-lived refresh token keeps the user logged in for up to 30 days without ever exposing a long-lived access token.

---

### 4. Google OAuth Sign-In

> **Requirement:** *"Users should be able to sign in using Google."*

**Implementation:** Firebase Authentication with Google provider on the client side, and Firebase Admin SDK verification on the server side.

#### Client Side (`firebase-config.js` + `google-auth.js`)

1. Firebase is initialized with the project's config.
2. A `GoogleAuthProvider` is created.
3. When the user clicks "Sign in with Google", a popup opens for Google authentication.
4. Upon success, a Firebase ID Token is retrieved and sent to the backend.

```javascript
auth.signInWithPopup(provider)
    .then((result) => result.user.getIdToken())
    .then((idToken) => {
        fetch('/google-login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: idToken })
        });
    });
```

#### Server Side (`app.py` — `/google-login` route)

1. The Firebase Admin SDK verifies the ID token using `firebase_auth.verify_id_token()`.
2. If the user doesn't exist in the local database, a new account is auto-created.
3. A session record is created, and JWT cookies (access + refresh) are issued.

```python
decoded_token = firebase_auth.verify_id_token(token, clock_skew_seconds=10)
email = decoded_token.get('email')
name = decoded_token.get('name', email.split('@')[0])

user = get_user_by_email(email)
if not user:
    random_password = secrets.token_urlsafe(16) + "aA1!"
    create_user(name, email, random_password)
```

**Security Note:** For Google-authenticated users, a cryptographically random password is generated (using `secrets.token_urlsafe(16)`) to satisfy the database schema. This password is never shared with the user and is unusable for direct login (since it's random).

---

### 5. Suspicious Login Detection

> **Requirement:** *"The system must detect suspicious login activities."*

**Implementation:** The **LoginLlama** API is integrated to perform real-time risk scoring on every login attempt.

```python
from loginllama import LoginLlama

loginllama = LoginLlama(api_token=os.environ['LOGINLLAMA_API_KEY'])

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
```

On every login attempt, the system sends:

| Data Point      | Source                      | Purpose                              |
|-----------------|-----------------------------|--------------------------------------|
| **User Email**  | Login form                  | Identify the account                 |
| **IP Address**  | `request.remote_addr`       | Detect unusual geographic locations  |
| **User Agent**  | `request.user_agent.string` | Detect unusual devices/browsers      |

LoginLlama analyses these signals against the user's historical login patterns and returns a **risk score**. This score is logged on the server for monitoring and can be used to trigger additional verification steps if needed.

---

### 6. Session Viewing & Management

> **Requirement:** *"Users should be able to view and manage their active sessions."*

**Implementation:** A sessions table in SQLite stores every login event. The home page dashboard displays all active sessions, and users can log out to revoke the current session.

#### Database Schema for Sessions

```sql
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    device TEXT,
    location TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'Active'
)
```

#### Session Creation (on Login)

Every successful login (both email/password and Google) creates a session record:

```python
device = f"{request.user_agent.platform.title()} ({request.user_agent.browser.title()})"
location = request.remote_addr
session_id = create_session(user[2], device, location)
```

The `session_id` is embedded into the JWT token as a custom claim, linking the token to the session:

```python
access_token = create_access_token(
    identity=user[2],
    additional_claims={"session_id": session_id}
)
```

#### Session Display (Home Page)

The home page shows all active sessions in a table with:

| Column   | Description                                           |
|----------|-------------------------------------------------------|
| Device   | OS and browser (e.g., "Windows (Chrome)")             |
| Location | IP address of the login                               |
| Status   | "Current Session" (highlighted green) or "Active"     |

#### Session Revocation

When a user logs out, their session is marked as `'Inactive'` in the database:

```python
def revoke_session_in_db(session_id, user_email):
    conn.execute(
        "UPDATE sessions SET status = 'Inactive' WHERE id = ? AND user_email = ?",
        (session_id, user_email)
    )
```

The JWT **token blocklist** checks the session status on every request. If a session is inactive, the token is treated as revoked:

```python
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    session_id = jwt_payload.get("session_id")
    # ... query DB ...
    return result and result[0] == 'Inactive'
```

This means revoking a session instantly invalidates its associated JWT tokens.

---

## API Endpoints

| Method | Endpoint        | Auth Required | Rate Limit     | Description                              |
|--------|-----------------|---------------|----------------|------------------------------------------|
| GET    | `/`             | No            | Default        | Redirects to `/home`                     |
| GET    | `/login`        | No            | 5/min          | Renders login page                       |
| POST   | `/login`        | No            | 5/min          | Authenticates user, issues JWT cookies   |
| GET    | `/register`     | No            | Default        | Renders registration page                |
| POST   | `/register`     | No            | Default        | Creates new user account                 |
| POST   | `/google-login` | No            | 5/min          | Verifies Firebase token, issues JWTs     |
| GET    | `/home`         | **Yes (JWT)** | Default        | Dashboard with session management        |
| GET    | `/refresh`      | **Yes (Refresh)** | Default    | Issues new access token using refresh    |
| GET    | `/logout`       | Optional JWT  | Default        | Revokes session, clears JWT cookies      |

---

## Setup & Installation

### Prerequisites

- Python 3.8+
- pip (Python package manager)
- A Firebase project with Google Sign-In enabled
- A LoginLlama API key

### Steps

1. **Clone the repository:**

   ```bash
   git clone <repository-url>
   cd auth
   ```

2. **Create a virtual environment:**

   ```bash
   python -m venv venv
   venv\Scripts\activate         
   ```

3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**  
   Create a `.env` file in the project root:

   ```env
   JWT_SECRET_KEY=<your-secret-key>
   LOGINLLAMA_API_KEY=<your-loginllama-api-key>
   ```

5. **Add Firebase credentials:**  
   Place your `firebase-adminsdk.json` service account file in the project root.

6. **Run the application:**

   ```bash
   python app.py
   ```

   The server starts at `http://127.0.0.1:5000`.

---
