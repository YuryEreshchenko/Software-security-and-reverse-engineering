# Web Security Demo — Three Implementation Levels

A simple **Flask** web application that demonstrates three common web security cases:
1. **Broken Authentication** — password check missing.
2. **SQL Injection** — user input concatenated directly into SQL.
3. **Secure Implementation** — parameterized queries, bcrypt hashing, and validation.

This project is educational and meant for **local / classroom use only**. It illustrates how small coding decisions can drastically change an app’s security level.

---

## Project Structure

```
.
├── app.py        # Main Flask application (3 login levels)
├── users.db      # SQLite database (auto-created on first run)
└── README.md
```

Each login form in the app corresponds to a different security level:

| Level | Route | Description |
|-------|--------|-------------|
| Level 1 | `/login_insecure` | No password verification — anyone can log in. |
| Level 2 | `/login_vulnerable` | SQL built via string concatenation — vulnerable to injection. |
| Level 3 | `/login_secure` | Proper input validation and parameterized queries. |

---

## Requirements

- **Python 3.8+**
- **pip** (Python package manager)
- Optional: `venv` or `virtualenv` for an isolated environment
- Python packages:
  - `Flask`
  - `bcrypt`

---

## Quick Setup — Windows PowerShell

```powershell
# 1. Go to your project folder
cd C:\path\to\project

# 2. (Optional) Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install Flask bcrypt

# 4. (Optional) Set a secret key
$env:FLASK_SECRET_KEY="replace_with_secure_random_value"

# 5. Run the app
python app.py
```

Once it’s running, open your browser to:
 **http://127.0.0.1:5000**

---

## Running the Application

When you start the app:
- It automatically creates `users.db` with two demo users:
  - `alice / password123`
  - `bob / securepass`
- You’ll see a homepage with three login boxes labeled *Level 1*, *Level 2*, and *Level 3*.

In your terminal, you’ll also see this summary:

```
Access at: http://127.0.0.1:5000
Test Accounts:
  • alice / password123
  • bob / securepass
Level 1: Any username grants access (no password check)
Level 2: Try SQL injection with: alice' OR '1'='1
Level 3: Properly secured against common attacks
```

---

## 🔍 How to Test Each Level

### Level 1 — Broken Authentication
- **Route:** `/login_insecure`
- **What happens:** Only checks if a username exists. Password is ignored.
- **Test:** Enter “alice” with an empty password → You’ll still log in.
- **Exploit type:** Broken access control.

### Level 2 — SQL Injection
- **Route:** `/login_vulnerable`
- **What happens:** Builds SQL via string concatenation.
- **Test payload:**  
  Username → `alice' OR '1'='1`  
  Password → anything  
  → Login bypasses authentication.
- **Exploit type:** SQL injection.

### Level 3 — Secure Implementation
- **Route:** `/login_secure`
- **What happens:** Uses parameterized queries and bcrypt password check.
- **Test:**  
  - Valid credentials (alice/password123) → login succeeds.  
  - Injection payload (`alice' OR '1'='1`) → login fails.
- **Exploit type:** None — input validated and query parameterized.

### Logout
- **Route:** `/logout` — clears session and redirects home.

---

## Verification Steps

1. **Run the app** → `python app.py`
2. **Test Level 1:** username-only login succeeds (vulnerable)
3. **Test Level 2:** injection payload `alice' OR '1'='1` bypasses login (vulnerable)
4. **Test Level 3:** same injection fails; correct credentials succeed (secure)
5. Optional — include screenshots of each step in your report.

---

## Security Notes & Good Practices

The app is intentionally insecure in the first two levels for learning.  
If you ever adapt this code to real usage, **always** apply these improvements:

- Use **parameterized queries** (`cursor.execute('SELECT ... WHERE username = ?', (username,))`)
- Validate and sanitize all user input (e.g., only allow alphanumeric usernames)
- Hash passwords with **bcrypt** or **Argon2**
- Do **not** store plain-text passwords
- Hide internal errors from users; log them server-side
- Use a secure random **secret key** via environment variable:
  ```python
  app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change_this_in_production')
  ```
- Enable secure session cookies:
  ```python
  app.config.update(
      SESSION_COOKIE_HTTPONLY=True,
      SESSION_COOKIE_SECURE=True,   # set to True if using HTTPS
      SESSION_COOKIE_SAMESITE='Lax'
  )
  ```
- Add **rate limiting** or lockout for repeated login failures
- Deploy behind HTTPS only

---


## License & Acknowledgements

This project is for **educational purposes only** — do **not** use it for unauthorized testing or real systems.  
Inspired by the OWASP Top 10 principles and classroom examples from typical Web Security assignments.

**Author:**  
**Course:** Web Security — Vulnerability Identification & Fixes  
**Instructor:**  
**Institution:** 
