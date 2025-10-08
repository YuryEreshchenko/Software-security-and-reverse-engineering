from flask import Flask, request, render_template_string, session, redirect
import bcrypt

app = Flask(__name__)
app.secret_key = 'demo_secret_key_change_in_production'

# Fake database (in real apps, this would be a real database)
users_db = {
    'alice': bcrypt.hashpw('password123'.encode(), bcrypt.gensalt()),
    'bob': bcrypt.hashpw('securepass'.encode(), bcrypt.gensalt())
}

# HTML templates (the web pages)
HOME_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Security Demo</title>
    <style>
        body { font-family: Arial; max-width: 800px; margin: 50px auto; }
        .warning { background: #ffcccc; padding: 20px; border-radius: 5px; }
        .safe { background: #ccffcc; padding: 20px; border-radius: 5px; }
        input { padding: 10px; margin: 10px 0; width: 300px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <h1>🔒 Security Demo Project</h1>
    <p><strong>Demo Users:</strong> alice/password123 or bob/securepass</p>
    
    <div style="display: flex; gap: 50px; margin-top: 30px;">
        <div class="warning">
            <h2>❌ INSECURE Login</h2>
            <p>This version has a security flaw!</p>
            <form method="POST" action="/login_insecure">
                <input name="username" placeholder="Username" required><br>
                <input name="password" type="password" placeholder="Password"><br>
                <button type="submit">Login (Insecure)</button>
            </form>
        </div>
        
        <div class="safe">
            <h2>✅ SECURE Login</h2>
            <p>This version is properly secured!</p>
            <form method="POST" action="/login_secure">
                <input name="username" placeholder="Username" required><br>
                <input name="password" type="password" placeholder="Password" required><br>
                <button type="submit">Login (Secure)</button>
            </form>
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
    <p>You are now logged in.</p>
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
# INSECURE VERSION (THE BUG)
# ========================================
@app.route('/login_insecure', methods=['POST'])
def login_insecure():
    username = request.form.get('username')
    password = request.form.get('password')  # We get it but don't use it!
    
    # SECURITY BUG: We only check if username exists!
    # We NEVER check the password!
    if username:
        session['user'] = username
        return SUCCESS_PAGE.format(username=username)
    
    return FAIL_PAGE.format(message="Username is required")

# ========================================
# SECURE VERSION (THE FIX)
# ========================================
@app.route('/login_secure', methods=['POST'])
def login_secure():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # SECURITY FIX: Properly check BOTH username AND password
    if not username or not password:
        return FAIL_PAGE.format(message="Username and password required")
    
    # Check if user exists in database
    if username not in users_db:
        return FAIL_PAGE.format(message="Invalid username or password")
    
    # Verify the password matches the stored hash
    stored_hash = users_db[username]
    if bcrypt.checkpw(password.encode(), stored_hash):
        session['user'] = username
        return SUCCESS_PAGE.format(username=username)
    
    return FAIL_PAGE.format(message="Invalid username or password")

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    print("\n" + "="*50)
    print("Starting Security Demo Server")
    print("="*50)
    print("\nOpen your browser and go to: http://127.0.0.1:5000")
    print("\nDemo accounts:")
    print("   • alice / password123")
    print("   • bob / securepass")
    print("\nry both login forms to see the difference!\n")
    app.run(debug=True, port=5000)