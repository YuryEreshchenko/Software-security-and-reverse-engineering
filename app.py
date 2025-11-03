from flask import Flask, request, render_template_string, session, redirect
import bcrypt
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'demo_secret_key_change_in_production'

# Initialize SQLite database
DB_PATH = 'users.db'

def init_db():
    """Initialize the database with sample users"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Insert demo users if they don't exist
    demo_users = [
        ('alice', bcrypt.hashpw('password123'.encode(), bcrypt.gensalt())),
        ('bob', bcrypt.hashpw('securepass'.encode(), bcrypt.gensalt()))
    ]
    
    for username, password_hash in demo_users:
        try:
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                         (username, password_hash))
        except sqlite3.IntegrityError:
            pass  # User already exists
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# HTML templates
HOME_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Security Demo - 3 Levels</title>
    <style>
        body { font-family: Arial; max-width: 1200px; margin: 50px auto; }
        .container { display: flex; gap: 30px; margin-top: 30px; }
        .box { flex: 1; padding: 20px; border-radius: 5px; }
        .warning { background: #ffcccc; border: 2px solid #ff0000; }
        .caution { background: #fff4cc; border: 2px solid #ffaa00; }
        .safe { background: #ccffcc; border: 2px solid #00aa00; }
        input { padding: 10px; margin: 10px 0; width: 90%; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        h2 { margin-top: 0; }
        .info { font-size: 0.9em; margin-top: 10px; }
    </style>
</head>
<body>
    <h1>🔒 Security Demo Project - Three Levels</h1>
    <p><strong>Demo Users:</strong> alice/password123 or bob/securepass</p>
    
    <div class="container">
        <!-- Level 1: Basic Authentication Bug -->
        <div class="box warning">
            <h2>❌ LEVEL 1: Insecure</h2>
            <p><strong>Vulnerability:</strong> Missing password check</p>
            <form method="POST" action="/login_insecure">
                <input name="username" placeholder="Username" required><br>
                <input name="password" type="password" placeholder="Password"><br>
                <button type="submit">Login</button>
            </form>
            <div class="info">
                <strong>Attack:</strong> Enter any username without password
            </div>
        </div>
        
        <!-- Level 2: SQL Injection -->
        <div class="box caution">
            <h2>⚠️ LEVEL 2: SQL Injection</h2>
            <p><strong>Vulnerability:</strong> Unvalidated SQL queries</p>
            <form method="POST" action="/login_vulnerable">
                <input name="username" placeholder="Username" required><br>
                <input name="password" type="password" placeholder="Password" required><br>
                <button type="submit">Login</button>
            </form>
            <div class="info">
                <strong>Attack:</strong> Try username: <code>alice' OR '1'='1</code>
            </div>
        </div>
        
        <!-- Level 3: Secure Implementation -->
        <div class="box safe">
            <h2>✅ LEVEL 3: Secure</h2>
            <p><strong>Protection:</strong> Parameterized queries + validation</p>
            <form method="POST" action="/login_secure">
                <input name="username" placeholder="Username" required><br>
                <input name="password" type="password" placeholder="Password" required><br>
                <button type="submit">Login</button>
            </form>
            <div class="info">
                <strong>Security:</strong> Input validation + prepared statements
            </div>
        </div>
    </div>
</body>
</html>
'''

SUCCESS_PAGE = '''
<!DOCTYPE html>
<html>
<body style="font-family: Arial; max-width: 800px; margin: 50px auto;">
    <h1>✅ Login Successful!</h1>
    <p>Welcome, <strong>{username}</strong>!</p>
    <p>Login method: <strong>{method}</strong></p>
    <a href="/logout"><button>Logout</button></a>
    <a href="/"><button>Back to Home</button></a>
</body>
</html>
'''

FAIL_PAGE = '''
<!DOCTYPE html>
<html>
<body style="font-family: Arial; max-width: 800px; margin: 50px auto;">
    <h1>❌ Login Failed</h1>
    <p style="color: red;">{message}</p>
    <a href="/"><button>Try Again</button></a>
</body>
</html>
'''

@app.route('/')
def home():
    return HOME_PAGE

# ========================================
# LEVEL 1: INSECURE (No password check)
# ========================================
@app.route('/login_insecure', methods=['POST'])
def login_insecure():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # BUG: Only checks if username exists, never validates password!
    if username:
        session['user'] = username
        return SUCCESS_PAGE.format(username=username, method="Level 1 - Insecure (No password check)")
    
    return FAIL_PAGE.format(message="Username is required")

# ========================================
# LEVEL 2: VULNERABLE (SQL Injection)
# ========================================
@app.route('/login_vulnerable', methods=['POST'])
def login_vulnerable():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return FAIL_PAGE.format(message="Username and password required")
    
    # VULNERABILITY: SQL Injection - building query with string concatenation
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # DANGEROUS: Direct string interpolation in SQL query
    query = f"SELECT username, password_hash FROM users WHERE username = '{username}'"
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        
        if result:
            stored_username, stored_hash = result
            # Check password
            if bcrypt.checkpw(password.encode(), stored_hash):
                session['user'] = stored_username
                return SUCCESS_PAGE.format(username=stored_username, method="Level 2 - SQL Injection Vulnerable")
        
        return FAIL_PAGE.format(message="Invalid username or password")
    
    except sqlite3.Error as e:
        conn.close()
        # In production, don't reveal SQL errors to users!
        return FAIL_PAGE.format(message=f"Database error: {str(e)}")

# ========================================
# LEVEL 3: SECURE (Parameterized queries)
# ========================================
@app.route('/login_secure', methods=['POST'])
def login_secure():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Input validation
    if not username or not password:
        return FAIL_PAGE.format(message="Username and password required")
    
    # Additional validation: restrict username format
    if not username.isalnum() or len(username) > 50:
        return FAIL_PAGE.format(message="Invalid username format")
    
    # SECURE: Use parameterized queries (prepared statements)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Safe: Parameters are properly escaped by the database driver
    cursor.execute('SELECT username, password_hash FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        stored_username, stored_hash = result
        # Verify password with bcrypt
        if bcrypt.checkpw(password.encode(), stored_hash):
            session['user'] = stored_username
            return SUCCESS_PAGE.format(username=stored_username, method="Level 3 - Secure (Parameterized queries)")
    
    # Generic error message to prevent username enumeration
    return FAIL_PAGE.format(message="Invalid username or password")

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    print("\n" + "="*60)
    print("Starting Security Demo Server - Three Levels")
    print("="*60)
    print("\nOpen your browser: http://127.0.0.1:5000")
    print("\nDemo accounts:")
    print("   • alice / password123")
    print("   • bob / securepass")
    print("\n🔴 Level 1: Try any username without password")
    print("🟡 Level 2: Try SQL injection: alice' OR '1'='1")
    print("🟢 Level 3: Secure implementation\n")
    app.run(debug=True, port=5000)