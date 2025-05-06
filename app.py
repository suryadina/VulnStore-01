import os
import sqlite3
import string
import random
import pyotp
import json
import jwt
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vulnerable_secret_key'
app.config['JWT_SECRET_KEY'] = 'secret123456'  # Weak JWT signing key
app.config['DATABASE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'store.db')
app.config['ADMIN_PATH'] = 'adminqwerty123'  # Static admin path

# Random password
def random_password(length=10):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))


# Initialize the database
def init_db():
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                balance INTEGER DEFAULT 100000,  -- Join bonus of IDR 100000
                is_admin INTEGER DEFAULT 0,
                totp_secret TEXT NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                price INTEGER NOT NULL,
                image TEXT
            );
            
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                comment TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            
            CREATE TABLE IF NOT EXISTS purchases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                price INTEGER NOT NULL,
                purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(product_id) REFERENCES products(id)
            );
            
            -- Insert sample products if they don't exist
            INSERT OR IGNORE INTO products (id, name, description, price, image) VALUES
                (1, 'Nasi Goreng Spesial', 'Nasi goreng lengkap dengan telur dan ayam suwir', 15000, 'nasi_goreng.jpg'),
                (2, 'Es Teh Manis', 'Minuman favorit rakyat Indonesia, segar dan manis', 5000, 'es_teh.jpg'),
                (3, 'Keripik Singkong Pedas', 'Camilan pedas renyah dari singkong asli', 8000, 'keripik_singkong.jpg'),
                (4, 'Martabak Manis', 'Martabak cokelat kacang keju yang lezat', 25000, 'martabak.jpg'),
                (5, 'Sate Ayam Madura', 'Sate ayam khas Madura dengan bumbu kacang', 20000, 'sate_ayam.jpg'),
                (6, 'Kopi Tubruk', 'Kopi hitam khas Jawa, diseduh langsung', 7000, 'kopi_tubruk.jpg'),
                (7, 'Pecel Lele', 'Lele goreng dengan sambal dan lalapan', 17000, 'pecel_lele.jpg'),
                (8, 'Batik Tulis', 'Kain batik tulis asli buatan pengrajin lokal', 250000, 'batik.jpg'),
                (9, 'Tas Anyaman Rotan', 'Tas tangan dari anyaman rotan alami', 150000, 'tas_rotan.jpg'),
                (10, 'Jus Alpukat Cokelat', 'Jus alpukat segar dengan topping cokelat kental', 12000, 'jus_alpukat.jpg'),
                (11, 'Tempe Mendoan', 'Tempe tipis goreng khas Purwokerto', 6000, 'tempe_mendoan.jpg'),
                (12, 'Kue Klepon', 'Kue ketan isi gula merah, ditaburi kelapa', 5000, 'klepon.jpg'),
                (13, 'Gelang Kayu Cendana', 'Aksesori natural dari kayu cendana harum', 45000, 'gelang_kayu.jpg'),
                (14, 'Minyak Kayu Putih', 'Minyak penghangat tubuh khas Indonesia', 25000, 'kayu_putih.jpg'),
                (15, 'Sambal Terasi', 'Sambal pedas dengan aroma terasi khas', 8000, 'sambal_terasi.jpg'),
                (16, 'Kaos Dagadu', 'Kaos lucu khas Jogja dengan desain unik', 85000, 'dagadu.jpg'),
                (17, 'Wayang Kulit Miniatur', 'Miniatur wayang kulit untuk hiasan rumah', 100000, 'wayang.jpg'),
                (18, 'Kerupuk Udang', 'Kerupuk gurih berbahan udang asli', 10000, 'kerupuk_udang.jpg'),
                (19, 'Gantungan Kunci Bali', 'Souvenir khas Bali berbentuk lucu', 15000, 'gantungan_bali.jpg'),
                (20, 'Emas Antam', 'Emas asli Antam', 10000000, 'emas_antam.jpg');
        ''')
        
        # Create default admin user if it doesn't exist
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        admin_exists = cursor.fetchone()
        
        if not admin_exists:
            admin_password = "YouCannotHackMe123"
            admin_totp_secret = "HVBHPBY62OPTQC7DGEGZ5LM24SSXVT6T"
            
            hashed_password = generate_password_hash(admin_password)
            cursor.execute(
                "INSERT INTO users (username, password, totp_secret, is_admin) VALUES (?, ?, ?, ?)",
                ("admin", hashed_password, admin_totp_secret, 1)
            )
            conn.commit()

        # Create 10 non-admin users if they don't exist
        # 10 Indonesian-style usernames
        usernames = [
            "agus_saputra",
            "dina_rahmawati",
            "budi_santoso",
            "siti_nuraini",
            "eko_prasetyo",
            "lina_mardiana",
            "joko_trihardjo",
            "ayu_wulandari",
            "hendri_setiawan",
            "fitri_andayani"
        ]

        shared_totp_secret = "HVBHPBY62OPTQC7DGEGZ5LM24SSXVT6T"

        # Create users
        for username in usernames:
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user_exists = cursor.fetchone()

            if not user_exists:
                plain_password = random_password()
                hashed_password = generate_password_hash(plain_password)
                cursor.execute(
                    "INSERT INTO users (username, password, totp_secret, is_admin) VALUES (?, ?, ?, ?)",
                    (username, hashed_password, shared_totp_secret, 0)
                )
                print(f"Created user '{username}' with password: {plain_password}")

        conn.commit()


        # Check how many purchases already exist
        cursor.execute("SELECT COUNT(*) FROM purchases")
        purchase_count = cursor.fetchone()[0]

        if purchase_count < 50:
            # First, fetch all user IDs
            cursor.execute("SELECT id FROM users WHERE username IN (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                "agus_saputra", "dina_rahmawati", "budi_santoso", "siti_nuraini", "eko_prasetyo",
                "lina_mardiana", "joko_trihardjo", "ayu_wulandari", "hendri_setiawan", "fitri_andayani"
            ))
            user_ids = [row[0] for row in cursor.fetchall()]

            # Fetch all products with their IDs and prices
            cursor.execute("SELECT id, price FROM products")
            products = cursor.fetchall()  # list of tuples: (product_id, price)

            # Insert 50 purchases
            for _ in range(50):
                user_id = random.choice(user_ids)
                product_id, price = random.choice(products)

                # Optional: create a random purchase date within the past 60 days
                days_ago = random.randint(0, 60)
                purchase_date = datetime.datetime.now() - datetime.timedelta(days=days_ago)
                
                cursor.execute(
                    "INSERT INTO purchases (user_id, product_id, price, purchase_date) VALUES (?, ?, ?, ?)",
                    (user_id, product_id, price, purchase_date)
                )

            conn.commit()
            print("Inserted 50 sample purchase transactions.")
        
        else:
            print("Purchse table already has 50 or more records. Skipping seeding.")


        # Check how many comments already exist
        cursor.execute("SELECT COUNT(*) FROM comments")
        comment_count = cursor.fetchone()[0]

        if comment_count < 10:
            # Get the 10 user IDs
            cursor.execute("SELECT id FROM users WHERE username IN (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                "agus_saputra", "dina_rahmawati", "budi_santoso", "siti_nuraini", "eko_prasetyo",
                "lina_mardiana", "joko_trihardjo", "ayu_wulandari", "hendri_setiawan", "fitri_andayani"
            ))
            user_ids = [row[0] for row in cursor.fetchall()]

            sample_comments = [
                "Barangnya bagus banget, terima kasih!",
                "Pengiriman cepat dan aman.",
                "Produk sesuai deskripsi.",
                "Harga terjangkau, kualitas oke.",
                "Puas banget belanja di sini.",
                "Akan belanja lagi nanti!",
                "Respon penjual cepat.",
                "Barang dalam kondisi baik.",
                "Sangat membantu, makasih!",
                "Suka banget sama produk ini!"
            ]

            for user_id, comment in zip(user_ids, sample_comments):
                days_ago = random.randint(0, 30)
                timestamp = (datetime.datetime.now() - datetime.timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")

                cursor.execute(
                    "INSERT INTO comments (user_id, comment, timestamp) VALUES (?, ?, ?)",
                    (user_id, comment, timestamp)
                )

            conn.commit()
            print("Seeded 10 comments (1 per user).")
        else:
            print("Comments table already has 10 or more records. Skipping seeding.")


# Get database connection
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# Generate JWT token
def generate_token(user_id, is_mfa_completed=False):
    payload = {
        'user_id': user_id,
        'is_mfa_completed': is_mfa_completed,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')

# Verify JWT token
def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Get token from request
def get_token():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        return auth_header.split(' ')[1]
    return request.cookies.get('jwt_token')

# Check if user is logged in - JWT only
def is_logged_in():
    token = get_token()
    if token:
        payload = verify_token(token)
        if payload and payload.get('is_mfa_completed', False):
            return True
    return False

# Get current user id - JWT only
def get_current_user_id():
    token = get_token()
    if token:
        payload = verify_token(token)
        if payload and payload.get('is_mfa_completed', False):
            return payload.get('user_id')
    return None

# Get current username
def get_current_username():
    user_id = get_current_user_id()
    if user_id:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if user:
                return user['username']
    return None

# Get user id regardless of MFA status - for setup processes
def get_user_id_no_mfa_check():
    token = get_token()
    if token:
        payload = verify_token(token)
        if payload:
            return payload.get('user_id')
    return None

# Check if user is admin - JWT only
def is_admin():
    user_id = get_current_user_id()
    if not user_id:
        return False
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if user and user['is_admin'] == 1:
            return True
        return False

# Routes will be defined below
@app.route('/')
def home():
    return render_template('index.html', 
                          logged_in=is_logged_in(), 
                          is_admin=is_admin(),
                          current_user_id=get_current_user_id(),
                          current_username=get_current_username())

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Generate TOTP secret
        totp_secret = pyotp.random_base32()
        
        with get_db() as conn:
            cursor = conn.cursor()
            try:
                hashed_password = generate_password_hash(password)
                cursor.execute(
                    "INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)",
                    (username, hashed_password, totp_secret)
                )
                conn.commit()
                
                # Get the user id for the new user
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()
                
                # Generate temporary token with MFA not completed
                temp_token = generate_token(user['id'], is_mfa_completed=False)
                
                # Redirect with token in cookie
                response = redirect(url_for('setup_totp'))
                response.set_cookie('jwt_token', temp_token, httponly=True, max_age=300)  # 5 minutes
                
                return response
            except sqlite3.IntegrityError:
                flash('Username already exists. Choose another username.')
    
    return render_template('register.html', current_user_id=get_current_user_id(), current_username=get_current_username())

@app.route('/setup_totp')
def setup_totp():
    # Use the new function that doesn't require MFA to be completed
    user_id = get_user_id_no_mfa_check()
    if not user_id:
        return redirect(url_for('login'))
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, totp_secret FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return redirect(url_for('login'))
        
        # Generate provisioning URI for QR code
        totp = pyotp.TOTP(user['totp_secret'])
        provisioning_url = totp.provisioning_uri(user['username'], issuer_name="Vulnerable Store")
        
    # Pass all the necessary template variables
    return render_template('setup_totp.html', 
                           provisioning_url=provisioning_url, 
                           secret=user['totp_secret'], 
                           current_user_id=user_id,
                           logged_in=False,  # User is not fully logged in yet
                           is_admin=False,
                           current_username=user['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password'], password):
                # Normal flow - generate a temporary token (MFA not completed)
                temp_token = generate_token(user['id'], is_mfa_completed=False)
                
                # Set the temporary token in cookie
                response = redirect(url_for('verify_totp'))
                response.set_cookie('jwt_token', temp_token, httponly=True, max_age=300)  # Short-lived token (5 min)
                return response
            else:
                flash('Invalid username or password')
    
    return render_template('login.html', current_user_id=get_current_user_id(), current_username=get_current_username())

@app.route('/verify_totp', methods=['GET', 'POST'])
def verify_totp():
    # Get user_id using our no-MFA-check function
    user_id = get_user_id_no_mfa_check()
    if not user_id:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        totp_code = request.form['totp_code']
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT totp_secret FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            
            if not user:
                return redirect(url_for('login'))
            
            # Verify TOTP code
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(totp_code):
                # Generate JWT token with MFA completed
                token = generate_token(user_id, is_mfa_completed=True)
                
                # Set token in cookie
                response = redirect(url_for('home'))
                response.set_cookie('jwt_token', token, httponly=True, max_age=3600)
                
                return response
            else:
                flash('Invalid authentication code')
    
    # Get username from user_id
    username = None
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            username = user_data['username']
    
    # Pass all the necessary template variables
    return render_template('verify_totp.html', 
                           current_user_id=user_id,
                           logged_in=False,  # User is not fully logged in yet
                           is_admin=False,
                           current_username=username)

# Helper endpoint to get user ID by username (intentionally vulnerable)
@app.route('/api/get_user_id/<username>', methods=['GET'])
def get_user_id_by_username(username):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user:
            return jsonify({
                'status': 'success',
                'user_id': user['id'],
                'username': username
            })
        else:
            return jsonify({'status': 'error', 'message': 'User not found'})

# Vulnerable endpoint for MFA bypass
# Note: Admin panel available at /adminqwerty123 (requires X-Forwarded-For: 127.0.0.1)
@app.route('/api/create_access_token', methods=['POST'])
def create_access_token():
    data = request.get_json()
    
    # Support both user_id or username in the request
    user_id = None
    if 'username' in data and 'password' in data:
        username = data['username']
        password = data['password']
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password'], password):
                user_id = user['id']
    elif 'temp_user_id' in data and 'password' in data:
        # Original implementation
        user_id = data['temp_user_id']
        password = data['password']
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            
            if not (user and check_password_hash(user['password'], password)):
                user_id = None
    
    if user_id:
        # Generate a JWT token with is_mfa_completed=True without actually verifying MFA
        token = generate_token(user_id, is_mfa_completed=True)
        
        # Return the token in the response
        return jsonify({
            'status': 'success', 
            'message': 'Access token created',
            'token': token
        })
    
    return jsonify({'status': 'error', 'message': 'Invalid credentials'})

@app.route('/logout')
def logout():
    # Clear JWT cookie only
    response = redirect(url_for('home'))
    response.delete_cookie('jwt_token')
    
    return response

# Catalog route with SQL injection vulnerability
@app.route('/catalog')
def catalog():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    # Vulnerable to SQL injection - using string formatting
    search = request.args.get('search', '')
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Vulnerable SQL query
        query = f"SELECT * FROM products WHERE name LIKE '%{search}%' OR description LIKE '%{search}%'"
        cursor.execute(query)
        products = cursor.fetchall()
    
    return render_template('catalog.html', products=products, logged_in=is_logged_in(), is_admin=is_admin(), current_user_id=get_current_user_id(), current_username=get_current_username())

# Product detail route
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        
        if not product:
            flash('Product not found')
            return redirect(url_for('catalog'))
    
    return render_template('product_detail.html', product=product, logged_in=is_logged_in(), is_admin=is_admin(), current_user_id=get_current_user_id(), current_username=get_current_username())

# Checkout route with price manipulation vulnerability
@app.route('/checkout', methods=['POST'])
def checkout():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for('login'))
    
    # Vulnerable implementation - accepts price from client
    product_id = request.form.get('product_id')
    price = int(request.form.get('price', 0))  # Accepts price from client!
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get user balance and product info
        cursor.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        
        if not user:
            flash('User not found')
            return redirect(url_for('catalog'))
        
        if not product:
            flash('Product not found')
            return redirect(url_for('catalog'))
        
        if user['balance'] < price:
            flash('Insufficient funds')
            return redirect(url_for('product_detail', product_id=product_id))
        
        # Update user balance
        cursor.execute(
            "UPDATE users SET balance = balance - ? WHERE id = ?",
            (price, user_id)
        )
        
        # Record the purchase
        cursor.execute(
            "INSERT INTO purchases (user_id, product_id, price) VALUES (?, ?, ?)",
            (user_id, product_id, price)
        )
        purchase_id = cursor.lastrowid
        conn.commit()
        
        # Redirect to success page
        return redirect(url_for('purchase_success', purchase_id=purchase_id))

# Purchase success page
@app.route('/purchase/success/<int:purchase_id>')
def purchase_success(purchase_id):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for('login'))
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get purchase details with product info
        cursor.execute("""
            SELECT p.id, p.price, p.purchase_date, pr.name, pr.description, u.username
            FROM purchases p
            JOIN products pr ON p.product_id = pr.id
            JOIN users u ON p.user_id = u.id
            WHERE p.id = ? AND p.user_id = ?
        """, (purchase_id, user_id))
        purchase = cursor.fetchone()
        
        if not purchase:
            flash('Purchase not found')
            return redirect(url_for('catalog'))
    
    return render_template('purchase_success.html', 
                          purchase=purchase, 
                          logged_in=is_logged_in(), 
                          is_admin=is_admin(),
                          current_user_id=get_current_user_id(),
                          current_username=get_current_username())

# User profile route with IDOR vulnerability - now using username
@app.route('/profile/<username>', methods=['GET', 'POST'])
def profile(username):
    if not is_logged_in():
        return redirect(url_for('login'))
    
    # Still vulnerable - no check if the requested username belongs to the logged-in user
    current_user_id = get_current_user_id()
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, balance FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            flash('User not found')
            return redirect(url_for('home'))
        
        # Get the user ID of the profile we're accessing
        user_id = user['id']
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        
        if new_password:
            with get_db() as conn:
                cursor = conn.cursor()
                hashed_password = generate_password_hash(new_password)
                
                # Update password without checking if user_id matches logged-in user
                cursor.execute(
                    "UPDATE users SET password = ? WHERE username = ?",
                    (hashed_password, username)
                )
                conn.commit()
                
                flash('Password updated successfully')
    
    return render_template('profile.html', user=user, logged_in=is_logged_in(), is_admin=is_admin(), current_user_id=get_current_user_id(), current_username=get_current_username())

# Company profile route with stored XSS vulnerability
@app.route('/company', methods=['GET', 'POST'])
def company():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    user_id = get_current_user_id()
    if not user_id:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        
        # Store comment without sanitization (vulnerable to stored XSS)
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO comments (user_id, comment) VALUES (?, ?)",
                (user_id, comment)
            )
            conn.commit()
            
            flash('Comment added')
    
    # Get all comments
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.comment, u.username, c.timestamp
            FROM comments c
            JOIN users u ON c.user_id = u.id
            ORDER BY c.timestamp DESC
        """)
        comments = cursor.fetchall()
    
    return render_template('company.html', comments=comments, logged_in=is_logged_in(), is_admin=is_admin(), current_user_id=get_current_user_id(), current_username=get_current_username())

# Admin panel with security checks
@app.route('/adminqwerty123')
def admin_panel():
    # Check if user is logged in and is admin
    if not is_logged_in() or not is_admin():
        # Unauthorized access attempt
        flash('Unauthorized access')
        return redirect(url_for('home'))
    
    # Additional security check - X-Forwarded-For header must be 127.0.0.1
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if not x_forwarded_for or x_forwarded_for != '127.0.0.1':
        # Incorrect header
        flash('Access denied: Invalid source')
        return redirect(url_for('home'))
    
    # If all checks pass, show admin panel
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get all users
        cursor.execute("SELECT id, username, balance, is_admin FROM users")
        users = cursor.fetchall()
        
        # Get all purchases with details
        cursor.execute("""
            SELECT p.id, p.user_id, p.product_id, p.price, p.purchase_date, 
                  u.username, pr.name as product_name
            FROM purchases p
            JOIN users u ON p.user_id = u.id
            JOIN products pr ON p.product_id = pr.id
            ORDER BY p.purchase_date DESC
        """)
        purchases = cursor.fetchall()
    
    return render_template('admin.html', 
                          users=users, 
                          purchases=purchases,
                          admin_path=app.config["ADMIN_PATH"], 
                          logged_in=is_logged_in(), 
                          is_admin=is_admin(), 
                          current_user_id=get_current_user_id(),
                          current_username=get_current_username())


if __name__ == '__main__':
    # Initialize the database
    init_db()
    # Print admin credentials
    print("\n===================================================")
    print("ADMIN CREDENTIALS:")
    print("---------------------------------------------------")
    print("Username: admin")
    print("Password: YouCannotHackMe123")
    print("TOTP Secret: HVBHPBY62OPTQC7DGEGZ5LM24SSXVT6T")
    print("Admin path: /adminqwerty123")
    print("X-Forwarded-For header required: 127.0.0.1")
    print("===================================================\n")
    # Run the app on port 62292 without debug mode
    app.run(debug=False, host='0.0.0.0', port=62292)