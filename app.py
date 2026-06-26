import os
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
import sqlite3
from datetime import datetime
import qrcode
from fpdf import FPDF
from functools import wraps
# Secure password hashing utilities
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "dalil_secure_key_system_2026" 

DB_FILE = "mydatabase.db"
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Authentication Protection Guard ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# --- Database Core Setup ---
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        # User Authentication Table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
        # ADDED 'username TEXT NOT NULL' to tie transaction data to a user
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dalilinfo (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                name TEXT, mobile TEXT, dec TEXT, date TEXT, catg TEXT, dr REAL, cr REAL
            )""")
        # ADDED 'username TEXT NOT NULL' and removed UNIQUE from mobile 
        # (different users might save the same customer mobile number)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                name TEXT NOT NULL, mobile TEXT NOT NULL, email TEXT, address TEXT, created_date TEXT
            )""")
        # ADDED 'username TEXT NOT NULL' to tie documents to a user
        conn.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                filename TEXT NOT NULL, description TEXT NOT NULL, uploaded_date TEXT NOT NULL
            )""")
        conn.commit()

init_db()

# --- Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        
        # Verify user exists and check the hashed password cryptographic match
        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid Username or Password!")
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match!")
            
        conn = get_db()
        # Verify if username is already taken
        existing_user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            return render_template('register.html', error="Username is already registered!")
            
        # Hash the password before saving to database
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            conn.execute("INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)",
                         (username, hashed_password, timestamp))
            conn.commit()
            return render_template('login.html', success="Registration successful! Please login.")
        except sqlite3.Error:
            return render_template('register.html', error="Database error occurred. Try again.")
            
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# --- Main Dashboard & Protected Routes ---
@app.route('/')
@login_required
def index():
    # Pass the session username into the template
    return render_template('index.html', username=session.get('username'))


@app.route('/api/transactions', methods=['GET'])
@login_required
def get_transactions():
    conn = get_db()
    # Filtered by logged-in user
    rows = conn.execute("SELECT * FROM dalilinfo WHERE username = ? ORDER BY id DESC", (session['username'],)).fetchall()
    return jsonify([dict(ix) for ix in rows])

@app.route('/api/transactions', methods=['POST'])
@login_required
def add_transaction():
    data = request.json
    conn = get_db()
    # Saved with the session username
    conn.execute("""
        INSERT INTO dalilinfo (username, name, mobile, dec, date, catg, dr, cr)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (session['username'], data['name'], data['mobile'], data['dec'], data['date'], data['catg'], float(data['dr'] or 0), float(data['cr'] or 0)))
    conn.commit()
    return jsonify({"status": "success"})

@app.route('/api/transactions/<int:rec_id>', methods=['DELETE'])
@login_required
def delete_transaction(rec_id):
    conn = get_db()
    # Double validation: ensuring the item actually belongs to the user attempting to delete it
    conn.execute("DELETE FROM dalilinfo WHERE id=? AND username=?", (rec_id, session['username']))
    conn.commit()
    return jsonify({"status": "deleted"})

@app.route('/api/customers/lookup/<mobile>', methods=['GET'])
@login_required
def lookup_customer(mobile):
    conn = get_db()
    # Filtered by logged-in user
    row = conn.execute("SELECT name, mobile FROM customers WHERE mobile = ? AND username = ?", (mobile, session['username'])).fetchone()
    if row:
        return jsonify({"found": True, "name": row['name']})
    return jsonify({"found": False})

@app.route('/customers')
@login_required
def customers_page():
    return render_template('customers.html')

# --- Consolidated Search-Enabled Customers Route ---
@app.route('/api/customers', methods=['GET', 'POST'])
@login_required
def handle_customers():
    conn = get_db()
    current_user = session['username']
    
    if request.method == 'GET':
        # Grab the search query parameter 'q'
        search_query = request.args.get('q', '').strip()
        
        if search_query:
            # Query with filters restricted strictly to user context
            sql = """
                SELECT * FROM customers 
                WHERE username = ? AND (name LIKE ? OR mobile LIKE ? OR email LIKE ?) 
                ORDER BY id DESC
            """
            like_param = f"%{search_query}%"
            rows = conn.execute(sql, (current_user, like_param, like_param, like_param)).fetchall()
        else:
            # Only fetch customers belonging to the logged-in user
            rows = conn.execute("SELECT * FROM customers WHERE username = ? ORDER BY id DESC", (current_user,)).fetchall()
            
        return jsonify([dict(r) for r in rows])
    
    data = request.json
    # Unique scoping: search for an existing entry within this user's dataset
    existing = conn.execute("SELECT id FROM customers WHERE mobile=? AND username=?", (data['mobile'], current_user)).fetchone()
    
    if not existing:
        conn.execute("""
            INSERT INTO customers (username, name, mobile, email, address, created_date)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (current_user, data['name'], data['mobile'], data['email'], data['address'], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    else:
        conn.execute("""
            UPDATE customers SET name=?, email=?, address=? WHERE mobile=? AND username=?""",
            (data['name'], data['email'], data['address'], data['mobile'], current_user))
    conn.commit()
    return jsonify({"status": "success"})

@app.route('/api/customers/<int:c_id>', methods=['DELETE'])
@login_required
def delete_customer(c_id):
    conn = get_db()
    conn.execute("DELETE FROM customers WHERE id=? AND username=?", (c_id, session['username']))
    conn.commit()
    return jsonify({"status": "success"})

@app.route('/documents')
@login_required
def documents_page():
    return render_template('documents.html')

@app.route('/api/documents/upload', methods=['POST'])
@login_required
def upload_document():
    if 'file' not in request.files: return redirect(request.url)
    file = request.files['file']
    desc = request.form.get('description', '')
    if file.filename == '': return redirect(request.url)
    
    if file and file.filename.lower().endswith('.pdf'):
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(id) FROM documents")
        max_id = cursor.fetchone()[0]
        next_id = (max_id + 1) if max_id else 1
        
        filename = f"{next_id}.pdf"
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        
        # Save filename linked to user
        conn.execute("INSERT INTO documents (username, filename, description, uploaded_date) VALUES (?, ?, ?, ?)",
                     (session['username'], filename, desc, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
    return redirect('/documents')

@app.route('/api/documents/open/<filename>')
@login_required
def open_document(filename):
    conn = get_db()
    # Secure validation check: verify user owns this physical filename entry before downloading
    doc = conn.execute("SELECT id FROM documents WHERE filename = ? AND username = ?", (filename, session['username'])).fetchone()
    if not doc:
        return "Access Denied: You do not own this document.", 403
    return send_file(os.path.join(UPLOAD_FOLDER, filename))

@app.route('/api/documents', methods=['GET'])
@login_required
def get_documents():
    conn = get_db()
    rows = conn.execute("SELECT * FROM documents WHERE username = ? ORDER BY id DESC", (session['username'],)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/documents/<int:doc_id>', methods=['DELETE'])
@login_required
def delete_document(doc_id):
    conn = get_db()
    # Confirm item ownership before disk/db clean up
    doc = conn.execute("SELECT filename FROM documents WHERE id = ? AND username = ?", (doc_id, session['username'])).fetchone()
    
    if doc:
        filename = doc['filename']
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        
        if os.path.exists(file_path):
            os.remove(file_path)
            
        conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
        conn.commit()
        return jsonify({"status": "success", "message": "Document deleted"})
        
    return jsonify({"status": "error", "message": "Document not found or unauthorized"}), 404

@app.route('/qr')
@login_required
def qr_page():
    return render_template('qr_gen.html')

@app.route('/api/qr/generate', methods=['POST'])
@login_required
def generate_qr():
    data = request.json
    content = data.get('content')
    filename = data.get('filename', 'qrcode')
    
    # Prepend username to filename to avoid folder conflicts among multiple users saving same title
    safe_filename = f"{session['username']}_{filename}.png"
    qr_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    img = qrcode.make(content)
    img.save(qr_path)
    return send_file(qr_path, as_attachment=True)

@app.route('/api/report/generate')
@login_required
def generate_pdf_report():
    mobile_filter = request.args.get('mobile')
    conn = get_db()
    current_user = session['username']
    
    # Filter report inputs explicitly using context parameters
    if mobile_filter:
        rows = conn.execute("SELECT name, mobile, dec, date, catg, dr, cr FROM dalilinfo WHERE mobile=? AND username=?", (mobile_filter, current_user)).fetchall()
        title = f"STATEMENT FOR MOBILE: {mobile_filter}"
    else:
        rows = conn.execute("SELECT name, mobile, dec, date, catg, dr, cr FROM dalilinfo WHERE username=?", (current_user,)).fetchall()
        title = f"{current_user.upper()}'S INFORMATION SYSTEM REPORT"
        
    if not rows: return "No data found", 404

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 15, title, 0, 1, 'C')
    pdf.ln(10)

    pdf.set_font("Arial", 'B', 10)
    col_widths = [35, 25, 50, 25, 20, 17, 17]
    for i, h in enumerate(["Name", "Mobile", "Description", "Date", "Catg", "Dr.", "Cr."]):
        pdf.cell(col_widths[i], 10, h, 1, 0, 'C')
    pdf.ln()

    pdf.set_font("Arial", '', 9)
    for r in rows:
        pdf.cell(col_widths[0], 8, str(r['name']), 1)
        pdf.cell(col_widths[1], 8, str(r['mobile']), 1)
        pdf.cell(col_widths[2], 8, str(r['dec']), 1)
        pdf.cell(col_widths[3], 8, str(r['date']), 1)
        pdf.cell(col_widths[4], 8, str(r['catg']), 1)
        pdf.cell(col_widths[5], 8, f"{r['dr']:.2f}", 1)
        pdf.cell(col_widths[6], 8, f"{r['cr']:.2f}", 1)
        pdf.ln()

    report_out = os.path.join(UPLOAD_FOLDER, f"{current_user}_generated_report.pdf")
    pdf.output(report_out)
    return send_file(report_out, as_attachment=False)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
