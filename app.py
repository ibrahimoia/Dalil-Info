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

# --- HARDCODED SUPER USER CREDENTIALS ---
SUPER_USER = "admin"
SUPER_PASSWORD = "ioi5454431"

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
        # User Authentication Table (with status tracking added)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active'
        )""")
        
        # Migration guard: Add status column if table existed before this update
        try:
            conn.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
        except sqlite3.OperationalError:
            pass  # Column already exists
            
        conn.execute("""
        CREATE TABLE IF NOT EXISTS dalilinfo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            name TEXT,
            mobile TEXT,
            dec TEXT,
            date TEXT,
            catg TEXT,
            dr REAL,
            cr REAL
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            name TEXT NOT NULL,
            mobile TEXT NOT NULL,
            email TEXT,
            address TEXT,
            created_date TEXT
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            filename TEXT NOT NULL,
            description TEXT NOT NULL,
            uploaded_date TEXT NOT NULL
        )""")
        
        # Seed the master admin user account if it doesn't already exist
        admin_check = conn.execute("SELECT id FROM users WHERE username = ?", (SUPER_USER,)).fetchone()
        if not admin_check:
            hashed_password = generate_password_hash(SUPER_PASSWORD)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute("INSERT INTO users (username, password, created_at, status) VALUES (?, ?, ?, 'active')", 
                         (SUPER_USER, hashed_password, timestamp))
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
        
        if user and check_password_hash(user['password'], password):
            # Check if user is suspended
            if user['status'] == 'suspended':
                return render_template('login.html', error="This account has been temporarily suspended. Please contact the administrator.")
                
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid Username or Password!")
            
    session.clear()
    return render_template('login.html')

# --- CHANGE PASSWORD ROUTE ---
@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.json or request.form
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_new_password = data.get('confirm_new_password')

    if not current_password or not new_password:
        return jsonify({"status": "error", "message": "Missing required password fields."}), 400

    if new_password != confirm_new_password:
        return jsonify({"status": "error", "message": "New passwords do not match."}), 400

    current_user = session['username']
    conn = get_db()
    user = conn.execute("SELECT password FROM users WHERE username = ?", (current_user,)).fetchone()

    if user and check_password_hash(user['password'], current_password):
        hashed_password = generate_password_hash(new_password)
        conn.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, current_user))
        conn.commit()
        return jsonify({"status": "success", "message": "Password changed successfully!"})
    else:
        return jsonify({"status": "error", "message": "Incorrect current password."}), 400

# --- USER MANAGEMENT WORKSPACE (Exclusively for SUPER_USER / admin) ---
@app.route('/users')
@login_required
def users_page():
    if session.get('username') != SUPER_USER:
        return "Access Denied: Only the super user can access user management dashboard.", 403
        
    conn = get_db()
    raw_users = conn.execute("SELECT id, username, created_at, status FROM users ORDER BY id DESC").fetchall()
    users_list = [dict(row) for row in raw_users]
    return render_template('users.html', system_users=users_list)

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if session.get('username') != SUPER_USER:
        return jsonify({"status": "error", "message": "Unauthorized Access"}), 403
        
    conn = get_db()
    target_user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if target_user and target_user['username'] == SUPER_USER:
        return jsonify({"status": "error", "message": "The Master Super User account cannot be deleted!"}), 400
        
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return jsonify({"status": "success", "message": "User deleted successfully"})

# New Endpoint: Suspend / Reactivate a user
@app.route('/api/users/<int:user_id>/status', methods=['POST'])
@login_required
def change_user_status(user_id):
    if session.get('username') != SUPER_USER:
        return jsonify({"status": "error", "message": "Unauthorized Access"}), 403
        
    data = request.json or {}
    new_status = data.get('status') # Expected values: 'active' or 'suspended'
    
    if new_status not in ['active', 'suspended']:
        return jsonify({"status": "error", "message": "Invalid status value provided"}), 400
        
    conn = get_db()
    target_user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not target_user:
        return jsonify({"status": "error", "message": "User not found"}), 404
        
    if target_user['username'] == SUPER_USER:
        return jsonify({"status": "error", "message": "The Master Super User account status cannot be altered!"}), 400
        
    conn.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    return jsonify({"status": "success", "message": f"User status changed to {new_status} successfully"})

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST' and 'super_username' in request.form:
        s_user = request.form.get('super_username').strip()
        s_pass = request.form.get('super_password')
        
        if s_user == SUPER_USER and s_pass == SUPER_PASSWORD:
            session['super_user_authenticated'] = True
            return render_template('register.html')
        else:
            return render_template('register.html', error="Invalid Super User Credentials!", show_super_login=True)

    if not session.get('super_user_authenticated'):
        return render_template('register.html', show_super_login=True)

    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match!")
            
        conn = get_db()
        existing_user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            return render_template('register.html', error="Username is already registered!")
            
        hashed_password = generate_password_hash(password)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            conn.execute("INSERT INTO users (username, password, created_at, status) VALUES (?, ?, ?, 'active')", (username, hashed_password, timestamp))
            conn.commit()
            return render_template('register.html', success=f"Account '{username}' created successfully!")
        except sqlite3.Error:
            return render_template('register.html', error="Database error occurred. Try again.")

    return render_template('register.html')

@app.route('/register/exit')
def exit_registration():
    session.pop('super_user_authenticated', None)
    return redirect(url_for('users_page'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('username'))

@app.route('/api/transactions', methods=['GET'])
@login_required
def get_transactions():
    conn = get_db()
    current_user = session['username']
    search_query = request.args.get('q', '').strip()
    
    if search_query:
        sql = """
        SELECT * FROM dalilinfo 
        WHERE username = ? AND (name LIKE ? OR mobile LIKE ? OR dec LIKE ? OR catg LIKE ?) 
        ORDER BY id DESC
        """
        like_param = f"%{search_query}%"
        rows = conn.execute(sql, (current_user, like_param, like_param, like_param, like_param)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM dalilinfo WHERE username = ? ORDER BY id DESC", (current_user,)).fetchall()
        
    return jsonify([dict(ix) for ix in rows])

@app.route('/api/transactions', methods=['POST'])
@login_required
def add_transaction():
    data = request.json
    conn = get_db()
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
    conn.execute("DELETE FROM dalilinfo WHERE id=? AND username=?", (rec_id, session['username']))
    conn.commit()
    return jsonify({"status": "deleted"})

# --- SAFE CUSTOMER LOOKUP ENDPOINT WITH QUERY PARAMETER ---
@app.route('/api/customers/lookup', methods=['GET'])
@login_required
def lookup_customer():
    mobile = request.args.get('mobile', '').strip()
    if not mobile:
        return jsonify({"found": False, "message": "Mobile missing"})
        
    conn = get_db()
    row = conn.execute("SELECT name, mobile FROM customers WHERE mobile = ? AND username = ?", (mobile, session['username'])).fetchone()
    if row:
        return jsonify({"found": True, "name": row['name']})
    
    return jsonify({
        "found": False, 
        "message": "this mobile not found , please record in customers",
        "redirect_url": "/customers"
    })

@app.route('/customers')
@login_required
def customers_page():
    return render_template('customers.html')

@app.route('/api/customers', methods=['GET', 'POST'])
@login_required
def handle_customers():
    conn = get_db()
    current_user = session['username']
    
    if request.method == 'GET':
        search_query = request.args.get('q', '').strip()
        if search_query:
            sql = """
            SELECT * FROM customers 
            WHERE username = ? AND (name LIKE ? OR mobile LIKE ? OR email LIKE ?) 
            ORDER BY id DESC
            """
            like_param = f"%{search_query}%"
            rows = conn.execute(sql, (current_user, like_param, like_param, like_param)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM customers WHERE username = ? ORDER BY id DESC", (current_user,)).fetchall()
        return jsonify([dict(r) for r in rows])
        
    if request.method == 'POST':
        data = request.json
        existing = conn.execute("SELECT id FROM customers WHERE mobile=? AND username=?", (data['mobile'], current_user)).fetchone()
        
        if not existing:
            conn.execute("""
            INSERT INTO customers (username, name, mobile, email, address, created_date) 
            VALUES (?, ?, ?, ?, ?, ?)""", 
            (current_user, data['name'], data['mobile'], data['email'], data['address'], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            return jsonify({"status": "success", "message": "Customer created successfully"})
        else:
            conn.execute("""
            UPDATE customers SET name=?, email=?, address=? 
            WHERE mobile=? AND username=?""", 
            (data['name'], data['email'], data['address'], data['mobile'], current_user))
            conn.commit()
            return jsonify({"status": "success", "message": "Customer updated via mobile number lookup"})

@app.route('/api/customers/<int:c_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def handle_single_customer(c_id):
    conn = get_db()
    current_user = session['username']
    
    if request.method == 'GET':
        row = conn.execute("SELECT * FROM customers WHERE id=? AND username=?", (c_id, current_user)).fetchone()
        if row:
            return jsonify(dict(row))
        return jsonify({"status": "error", "message": "Customer not found"}), 404
        
    elif request.method == 'PUT':
        data = request.json
        conn.execute("""
        UPDATE customers SET name=?, mobile=?, email=?, address=? 
        WHERE id=? AND username=?""", 
        (data['name'], data['mobile'], data['email'], data['address'], c_id, current_user))
        conn.commit()
        return jsonify({"status": "success", "message": "Customer updated successfully"})
        
    elif request.method == 'DELETE':
        conn.execute("DELETE FROM customers WHERE id=? AND username=?", (c_id, current_user))
        conn.commit()
        return jsonify({"status": "success", "message": "Customer deleted successfully"})

@app.route('/documents')
@login_required
def documents_page():
    return render_template('documents.html')

@app.route('/api/documents/upload', methods=['POST'])
@login_required
def upload_document():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    desc = request.form.get('description', '')
    
    if file.filename == '':
        return redirect(request.url)
        
    if file and file.filename.lower().endswith('.pdf'):
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(id) FROM documents")
        max_id = cursor.fetchone()[0]
        next_id = (max_id + 1) if max_id else 1
        
        filename = f"{next_id}.pdf"
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        
        conn.execute("INSERT INTO documents (username, filename, description, uploaded_date) VALUES (?, ?, ?, ?)", 
                     (session['username'], filename, desc, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        return redirect('/documents')

@app.route('/api/documents/open/<filename>')
@login_required
def open_document(filename):
    conn = get_db()
    doc = conn.execute("SELECT id FROM documents WHERE filename = ? AND username = ?", (filename, session['username'])).fetchone()
    if not doc:
        return "Access Denied: You do not own this document.", 403
    return send_file(os.path.join(UPLOAD_FOLDER, filename))

@app.route('/api/documents', methods=['GET'])
@login_required
def get_documents():
    conn = get_db()
    current_user = session['username']
    search_query = request.args.get('q', '').strip()
    
    if search_query:
        sql = """
        SELECT * FROM documents 
        WHERE username = ? AND (filename LIKE ? OR description LIKE ?) 
        ORDER BY id DESC
        """
        like_param = f"%{search_query}%"
        rows = conn.execute(sql, (current_user, like_param, like_param)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM documents WHERE username = ? ORDER BY id DESC", (current_user,)).fetchall()
        
    return jsonify([dict(r) for r in rows])

@app.route('/api/documents/<int:doc_id>', methods=['DELETE'])
@login_required
def delete_document(doc_id):
    conn = get_db()
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
    
    safe_filename = f"{session['username']}_{filename}.png"
    qr_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    
    img = qrcode.make(content)
    img.save(qr_path)
    return send_file(qr_path, as_attachment=True)

# --- REDESIGNED PDF REPORT GENERATION ---
@app.route('/api/report/generate')
@login_required
def generate_pdf_report():
    mobile_filter = request.args.get('mobile')
    conn = get_db()
    current_user = session['username']
    customer_name = None
    customer_address = None
    
    if mobile_filter:
        rows = conn.execute("SELECT name, mobile, dec, date, catg, dr, cr FROM dalilinfo WHERE mobile=? AND username=?", (mobile_filter, current_user)).fetchall()
        title = "ACCOUNT STATEMENT"
        
        # Pull metadata matching filter variables from the master customer record
        customer_row = conn.execute("SELECT name, address FROM customers WHERE mobile = ? AND username = ?", (mobile_filter, current_user)).fetchone()
        if customer_row:
            customer_name = customer_row['name']
            customer_address = customer_row['address']
        elif rows:
            # Fallback choice when missing an entry mapping directly to the dedicated directory
            customer_name = rows[0]['name']
    else:
        rows = conn.execute("SELECT name, mobile, dec, date, catg, dr, cr FROM dalilinfo WHERE username=?", (current_user,)).fetchall()
        title = f"{current_user.upper()}'S SYSTEM ACTIVITY REPORT"
        
    if not rows:
        return "No data found", 404
        
    pdf = FPDF()
    pdf.set_margins(15, 15, 15)
    pdf.add_page()
    
    # --- Structural Visual Header Layout ---
    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(44, 62, 80) # Modern dark slate color
    pdf.cell(0, 10, title, 0, 1, 'L')
    
    # Elegant Rule Divider Line
    pdf.set_draw_color(44, 62, 80)
    pdf.set_line_width(0.5)
    pdf.line(15, 27, 195, 27)
    pdf.ln(5)
    
    # Target Meta Metadata Context Fields
    if customer_name or mobile_filter:
        pdf.set_text_color(60, 60, 60)
        
        if customer_name:
            # Main Requirement: Bold customer name highlighted cleanly in structural workspace header
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(35, 6, "Customer Name:", 0, 0, 'L')
            pdf.cell(0, 6, str(customer_name), 0, 1, 'L')
            
        if mobile_filter:
            pdf.set_font("Arial", '', 10)
            pdf.cell(35, 6, "Mobile Number:", 0, 0, 'L')
            pdf.cell(0, 6, str(mobile_filter), 0, 1, 'L')
            
        if customer_address:
            pdf.set_font("Arial", '', 10)
            pdf.cell(35, 6, "Address:", 0, 0, 'L')
            pdf.cell(0, 6, str(customer_address), 0, 1, 'L')
            
        pdf.ln(3)
        
    # Bottom Alignment Right Timestamp Block
    pdf.set_font("Arial", 'I', 9)
    pdf.set_text_color(130, 130, 130)
    pdf.cell(0, 5, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'R')
    pdf.ln(4)
    
    # --- Clean Data Grid Layout ---
    col_widths = [32, 25, 48, 25, 18, 16, 16] 
    headers = ["Name", "Mobile", "Description", "Date", "Catg", "Dr.", "Cr."]
    
    # Apply Header Styles
    pdf.set_fill_color(44, 62, 80)
    pdf.set_text_color(255, 255, 255)
    pdf.set_draw_color(220, 220, 220)
    pdf.set_line_width(0.2)
    pdf.set_font("Arial", 'B', 9)
    
    for i, h in enumerate(headers):
        align_mode = 'R' if h in ["Dr.", "Cr."] else 'L'
        pdf.cell(col_widths[i], 9, h, 1, 0, align_mode, True)
    pdf.ln()
    
    # Processing Data Streams to Rows with Shading
    total_dr = 0.0
    total_cr = 0.0
    apply_stripe = False
    
    pdf.set_font("Arial", '', 9)
    for r in rows:
        dr_val = float(r['dr'] or 0)
        cr_val = float(r['cr'] or 0)
        total_dr += dr_val
        total_cr += cr_val
        
        # Alternating background track highlights
        pdf.set_fill_color(248, 249, 250) if apply_stripe else pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(50, 50, 50)
        
        # String Truncation Guards prevent clipping or breaking layout parameters
        pdf.cell(col_widths[0], 8, f" {str(r['name'])[:18]}", 1, 0, 'L', True)
        pdf.cell(col_widths[1], 8, f" {str(r['mobile'])}", 1, 0, 'L', True)
        pdf.cell(col_widths[2], 8, f" {str(r['dec'])[:28]}", 1, 0, 'L', True)
        pdf.cell(col_widths[3], 8, f" {str(r['date'])}", 1, 0, 'L', True)
        pdf.cell(col_widths[4], 8, f" {str(r['catg'])[:10]}", 1, 0, 'L', True)
        pdf.cell(col_widths[5], 8, f"{dr_val:.2f} ", 1, 0, 'R', True)
        pdf.cell(col_widths[6], 8, f"{cr_val:.2f} ", 1, 1, 'R', True)
        
        apply_stripe = not apply_stripe
        
    # --- Consolidated Ledger Totals Summary Block ---
    pdf.ln(2)
    pdf.set_font("Arial", 'B', 9)
    pdf.set_text_color(44, 62, 80)
    
    pdf.cell(sum(col_widths[:5]), 8, "Total Summary  ", 1, 0, 'R')
    pdf.cell(col_widths[5], 8, f"{total_dr:.2f} ", 1, 0, 'R')
    pdf.cell(col_widths[6], 8, f"{total_cr:.2f} ", 1, 1, 'R')
    
    # Calculated Delta Remainder Balance Value Row Block
    net_balance = total_dr - total_cr
    balance_label = f"Net Balance ({'Dr' if net_balance >= 0 else 'Cr'})  "
    
    pdf.cell(sum(col_widths[:5]), 8, balance_label, 1, 0, 'R')
    # Soft Green tint for positive balance, Soft Red tint for negative balance
    pdf.set_fill_color(235, 245, 235) if net_balance >= 0 else pdf.set_fill_color(255, 235, 235)
    pdf.cell(sum(col_widths[5:]), 8, f"{abs(net_balance):.2f} ", 1, 1, 'R', True)
    
    report_out = os.path.join(UPLOAD_FOLDER, f"{current_user}_generated_report.pdf")
    pdf.output(report_out)
    return send_file(report_out, as_attachment=False)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
