import os
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
import pymysql
import pymysql.cursors
from datetime import datetime
import qrcode
from fpdf import FPDF
from functools import wraps
# Secure password hashing utilities
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "dalil_secure_key_system_2026" 

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
    # Update these connection parameters with your MySQL setup credentials
    return pymysql.connect(
        host='localhost',
        user='root',
        password='your_mysql_password',
        database='your_database_name',
        cursorclass=pymysql.cursors.DictCursor, # Matches SQLite's row_factory behavior
        autocommit=False
    )

def init_db():
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            # User Authentication Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    created_at DATETIME NOT NULL
                )""")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dalilinfo (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255), mobile VARCHAR(50), `dec` TEXT, date VARCHAR(50), catg VARCHAR(100), dr DOUBLE, cr DOUBLE
                )""")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS customers (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL, mobile VARCHAR(50) UNIQUE NOT NULL, email VARCHAR(255), address TEXT, created_date DATETIME
                )""")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL, description TEXT NOT NULL, uploaded_date DATETIME NOT NULL
                )""")
        conn.commit()
    finally:
        conn.close()

# Initialize tables on startup
init_db()

# --- Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        
        conn = get_db()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()
            
            # Verify user exists and check the hashed password cryptographic match
            if user and check_password_hash(user['password'], password):
                session['logged_in'] = True
                session['username'] = username
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error="Invalid Username or Password!")
        finally:
            conn.close()
            
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
        try:
            with conn.cursor() as cursor:
                # Verify if username is already taken
                cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
                existing_user = cursor.fetchone()
                if existing_user:
                    return render_template('register.html', error="Username is already registered!")
                
                # Hash the password before saving to database
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                cursor.execute("INSERT INTO users (username, password, created_at) VALUES (%s, %s, %s)",
                               (username, hashed_password, timestamp))
            conn.commit()
            return render_template('login.html', success="Registration successful! Please login.")
        except Exception:
            conn.rollback()
            return render_template('register.html', error="Database error occurred. Try again.")
        finally:
            conn.close()
            
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# --- Main Dashboard & Protected Routes ---
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/transactions', methods=['GET'])
@login_required
def get_transactions():
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM dalilinfo ORDER BY id DESC")
            rows = cursor.fetchall()
        return jsonify(rows) # PyMySQL DictCursor already formats data into a list of dicts
    finally:
        conn.close()

@app.route('/api/transactions', methods=['POST'])
@login_required
def add_transaction():
    data = request.json
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO dalilinfo (name, mobile, `dec`, date, catg, dr, cr)
                VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (data['name'], data['mobile'], data['dec'], data['date'], data['catg'], float(data['dr'] or 0), float(data['cr'] or 0)))
        conn.commit()
        return jsonify({"status": "success"})
    except Exception:
        conn.rollback()
        return jsonify({"status": "error"}), 500
    finally:
        conn.close()

@app.route('/api/transactions/<int:rec_id>', methods=['DELETE'])
@login_required
def delete_transaction(rec_id):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM dalilinfo WHERE id=%s", (rec_id,))
        conn.commit()
        return jsonify({"status": "deleted"})
    except Exception:
        conn.rollback()
        return jsonify({"status": "error"}), 500
    finally:
        conn.close()

@app.route('/api/customers/lookup/<mobile>', methods=['GET'])
@login_required
def lookup_customer(mobile):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT name, mobile FROM customers WHERE mobile = %s", (mobile,))
            row = cursor.fetchone()
        if row:
            return jsonify({"found": True, "name": row['name']})
        return jsonify({"found": False})
    finally:
        conn.close()

@app.route('/customers')
@login_required
def customers_page():
    return render_template('customers.html')

@app.route('/api/customers', methods=['GET', 'POST'])
@login_required
def handle_customers():
    conn = get_db()
    try:
        if request.method == 'GET':
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM customers ORDER BY id DESC")
                rows = cursor.fetchall()
            return jsonify(rows)
        
        data = request.json
        with conn.cursor() as cursor:
            try:
                cursor.execute("""
                    INSERT INTO customers (name, mobile, email, address, created_date)
                    VALUES (%s, %s, %s, %s, %s)""",
                    (data['name'], data['mobile'], data['email'], data['address'], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                conn.commit()
            except pymysql.errors.IntegrityError:
                conn.rollback() # Clear the failed transaction state
                cursor.execute("""
                    UPDATE customers SET name=%s, email=%s, address=%s WHERE mobile=%s""",
                    (data['name'], data['email'], data['address'], data['mobile']))
                conn.commit()
        return jsonify({"status": "success"})
    except Exception:
        conn.rollback()
        return jsonify({"status": "error"}), 500
    finally:
        conn.close()

@app.route('/api/customers/<int:c_id>', methods=['DELETE'])
@login_required
def delete_customer(c_id):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM customers WHERE id=%s", (c_id,))
        conn.commit()
        return jsonify({"status": "success"})
    except Exception:
        conn.rollback()
        return jsonify({"status": "error"}), 500
    finally:
        conn.close()

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
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT MAX(id) FROM documents")
                result = cursor.fetchone()
                # When using DictCursor, MAX(id) will be returned with key 'MAX(id)'
                max_id = result['MAX(id)'] if result else None
                next_id = (max_id + 1) if max_id else 1
                
                filename = f"{next_id}.pdf"
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                
                cursor.execute("INSERT INTO documents (filename, description, uploaded_date) VALUES (%s, %s, %s)",
                             (filename, desc, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
        except Exception:
            conn.rollback()
        finally:
            conn.close()
    return redirect('/documents')

@app.route('/api/documents/open/<filename>')
@login_required
def open_document(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename))

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
    
    qr_path = os.path.join(UPLOAD_FOLDER, f"{filename}.png")
    img = qrcode.make(content)
    img.save(qr_path)
    return send_file(qr_path, as_attachment=True)

@app.route('/api/report/generate')
@login_required
def generate_pdf_report():
    mobile_filter = request.args.get('mobile')
    conn = get_db()
    
    try:
        with conn.cursor() as cursor:
            if mobile_filter:
                cursor.execute("SELECT name, mobile, `dec`, date, catg, dr, cr FROM dalilinfo WHERE mobile=%s", (mobile_filter,))
                rows = cursor.fetchall()
                title = f"STATEMENT FOR MOBILE: {mobile_filter}"
            else:
                cursor.execute("SELECT name, mobile, `dec`, date, catg, dr, cr FROM dalilinfo")
                rows = cursor.fetchall()
                title = "DALIL INFORMATION SYSTEM REPORT"
    finally:
        conn.close()
        
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

    report_out = os.path.join(UPLOAD_FOLDER, "generated_report.pdf")
    pdf.output(report_out)
    return send_file(report_out, as_attachment=False)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
