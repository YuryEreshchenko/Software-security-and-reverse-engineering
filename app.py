from flask import Flask, request, render_template_string, session, redirect
import bcrypt
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'demo_secret_key_change_in_production'

DB_PATH = 'users.db'

# ============================================================================
# Database Setup
# ============================================================================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create the users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Add demo users for testing
    demo_users = [
        ('alice', bcrypt.hashpw('password123'.encode(), bcrypt.gensalt())),
        ('bob', bcrypt.hashpw('securepass'.encode(), bcrypt.gensalt()))
    ]
    
    for username, password_hash in demo_users:
        try:
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                         (username, password_hash))
        except sqlite3.IntegrityError:
            pass  # User already exists, skip
    
    conn.commit()
    conn.close()

init_db()

# ============================================================================
# HTML Templates
# ============================================================================

HOME_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Security Demo - 3 Levels</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 1200px; 
            margin: 50px auto; 
            padding: 0 20px;
        }
        .container { 
            display: flex; 
            gap: 30px; 
            margin-top: 30px; 
        }
        .box { 
            flex: 1; 
            padding: 20px; 
            border-radius: 8px; 
        }
        .warning { 
            background: #ffcccc; 
            border: 2px solid #ff0000; 
        }
        .caution { 
            background: #fff4cc; 
            border: 2px solid #ffaa00; 
        }
        .safe { 
            background: #ccffcc; 
            border: 2px solid #00aa00; 
        }
        input { 
            padding: 10px; 
            margin: 10px 0; 
            width: 90%; 
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        button { 
            padding: 10px 20px; 
            background: #007bff; 
            color: white; 
            border: none; 
            cursor: pointer; 
            border-radius: 4px;
        }
        button:hover { 
            background: #0056b3; 
        }
        h2 { 
            margin-top: 0; 
        }
        .info { 
            font-size: 0.9em; 
            margin-top: 15px; 
            padding-top: 10px;
            border-top: 1px solid rgba(0,0,0,0.1);
        }
        code {
            background: rgba(0,0,0,0.1);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <h1>Security Demo - Three Implementation Levels</h1>
    <p><strong>Test Credentials:</strong> alice/password123 or bob/securepass</p>
    
    <div class="container">
        <!-- Implementation 1: Missing Authentication Check -->
        <div class="box warning">
            <h2>Level 1: Broken Authentication</h2>
            <p><strong>Issue:</strong> Password verification is missing</p>
            <form method="POST" action="/login_insecure">
                <input name="username" placeholder="Username" required><br>
                <input name="password" type="password" placeholder="Password"><br>
                <button type="submit">Login</button>
            </form>
            <div class="info">
                <strong>Exploit:</strong> Enter any valid username without a password
            </div>
        </div>
        
        <!-- Implementation 2: SQL Injection Vulnerability -->
        <div class="box caution">
            <h2>Level 2: SQL Injection</h2>
            <p><strong>Issue:</strong> User input directly concatenated in SQL query</p>
            <form method="POST" action="/login_vulnerable">
                <input name="username" placeholder="Username" required><br>
                <input name="password" type="password" placeholder="Password" required><br>
                <button type="submit">Login</button>
            </form>
            <div class="info">
                <strong>Exploit:</strong> Username: <code>alice' OR '1'='1</code>
            </div>
        </div>
        
        <!-- Implementation 3: Properly Secured -->
        <div class="box safe">
            <h2>Level 3: Secure Implementation</h2>
            <p><strong>Protection:</strong> Parameterized queries with input validation</p>
            <form method="POST" action="/login_secure">
                <input name="username" placeholder="Username" required><br>
                <input name="password" type="password" placeholder="Password" required><br>
                <button type="submit">Login</button>
            </form>
            <div class="info">
                <strong>Features:</strong> Prepared statements, input sanitization, proper error handling
            </div>
        </div>
    </div>
</body>
</html>
'''

SUCCESS_PAGE = '''
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px;">
    <h1 style="color: #28a745;">Login Successful</h1>
    <p>Welcome back, <strong>{username}</strong></p>
    <p>Authentication method: <strong>{method}</strong></p>
    <div style="margin-top: 30px;">
        <a href="/logout"><button style="padding: 10px 20px; margin-right: 10px;">Logout</button></a>
        <a href="/"><button style="padding: 10px 20px;">Return to Home</button></a>
    </div>
</body>
</html>
'''

FAIL_PAGE = '''
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px;">
    <h1 style="color: #dc3545;">Authentication Failed</h1>
    <p style="color: #dc3545; font-size: 1.1em;">{message}</p>
    <div style="margin-top: 30px;">
        <a href="/"><button style="padding: 10px 20px;">Try Again</button></a>
    </div>
</body>
</html>
'''

# ============================================================================
# Routes
# ============================================================================

@app.route('/')
def home():
    return HOME_PAGE

# ----------------------------------------------------------------------------
# Level 1: Insecure - No Password Verification
# ----------------------------------------------------------------------------

@app.route('/login_insecure', methods=['POST'])
def login_insecure():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Bug: only verifies username exists, password is completely ignored
    if username:
        session['user'] = username
        return SUCCESS_PAGE.format(
            username=username, 
            method="Level 1 - Insecure (Missing password check)"
        )
    
    return FAIL_PAGE.format(message="Username is required")

# ----------------------------------------------------------------------------
# Level 2: Vulnerable - SQL Injection
# ----------------------------------------------------------------------------

@app.route('/login_vulnerable', methods=['POST'])
def login_vulnerable():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return FAIL_PAGE.format(message="Both username and password are required")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Vulnerability: string concatenation allows SQL injection
    # An attacker can manipulate the query structure
    query = f"SELECT username, password_hash FROM users WHERE username = '{username}'"
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        
        if result:
            stored_username, stored_hash = result
            
            # Verify the password hash
            if bcrypt.checkpw(password.encode(), stored_hash):
                session['user'] = stored_username
                return SUCCESS_PAGE.format(
                    username=stored_username, 
                    method="Level 2 - Vulnerable to SQL Injection"
                )
        
        return FAIL_PAGE.format(message="Invalid credentials")
    
    except sqlite3.Error as e:
        conn.close()
        # Note: exposing database errors is also a security issue
        return FAIL_PAGE.format(message=f"Database error: {str(e)}")

# ----------------------------------------------------------------------------
# Level 3: Secure - Parameterized Queries + Validation
# ----------------------------------------------------------------------------

@app.route('/login_secure', methods=['POST'])
def login_secure():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Validate both fields are present
    if not username or not password:
        return FAIL_PAGE.format(message="Both username and password are required")
    
    # Validate username format: alphanumeric only, reasonable length
    if not username.isalnum() or len(username) > 50:
        return FAIL_PAGE.format(message="Invalid username format")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Use parameterized query to prevent SQL injection
    # The '?' placeholder ensures proper escaping by the database driver
    cursor.execute(
        'SELECT username, password_hash FROM users WHERE username = ?', 
        (username,)
    )
    result = cursor.fetchone()
    conn.close()
    
    if result:
        stored_username, stored_hash = result
        
        # Verify password using bcrypt
        if bcrypt.checkpw(password.encode(), stored_hash):
            session['user'] = stored_username
            return SUCCESS_PAGE.format(
                username=stored_username, 
                method="Level 3 - Secure (Parameterized queries)"
            )
    
    # Use generic error message to prevent username enumeration attacks
    return FAIL_PAGE.format(message="Invalid credentials")

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("Security Demo Server - Three Implementation Levels")
    print("="*60)
    print("\nAccess at: http://127.0.0.1:5000")
    print("\nTest Accounts:")
    print("  • alice / password123")
    print("  • bob / securepass")
    print("\nLevel 1: Any username grants access (no password check)")
    print("Level 2: Try SQL injection with: alice' OR '1'='1")
    print("Level 3: Properly secured against common attacks\n")
    
    app.run(debug=True, port=5000)