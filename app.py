from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
import sqlite3
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from database import create_users_table, drop_users_table, create_passwords_table, drop_passwords_table, update_password_in_db, add_password, search_passwords, get_passwords, delete_password, cipher
import pyotp  # Import pyotp
import qrcode
import io
import base64
from flask import send_file
#comment
app = Flask(__name__)
app.secret_key = 'testingsecretkey'
login_manager = LoginManager(app)
login_manager.login_view = 'login'
PASSCODE = "test"

class User(UserMixin):
    def __init__(self, id, username, password, otp_secret=None):
        self.id = id
        self.username = username
        self.password = password
        self.otp_secret = otp_secret or pyotp.random_base32()

@login_manager.user_loader
def load_user(user_id):
    connection = sqlite3.connect('passwords.db')
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    connection.close()
    if user:
        return User(id=user[0], username=user[1], password=user[2])
    return None

@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        encrypted_password = cipher.encrypt(password.encode()).decode('utf-8')
        otp_secret = pyotp.random_base32()

        try:
            connection = sqlite3.connect('passwords.db')
            cursor = connection.cursor()
            cursor.execute("INSERT INTO users (username, email, password, otp_secret) VALUES (?, ?, ?, ?)", 
                           (username, email, encrypted_password, otp_secret))
            connection.commit()
            connection.close()
            flash('Registration successful', 'success')
            session['otp_secret'] = otp_secret
            session['username'] = username
            return redirect(url_for('setup_otp'))
        except Exception as e:
            flash(f'Error: {e}', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/setup_otp')
def setup_otp():
    otp_secret = session.get('otp_secret')
    if not otp_secret or not is_valid_base32(otp_secret):
        flash('Invalid OTP secret. Please log in again.', 'danger')
        return redirect(url_for('login'))

    username = session.get('username')
    if not otp_secret or not username:
        flash('Invalid session. Please register again.', 'danger')
        return redirect(url_for('register'))
    totp = pyotp.TOTP(otp_secret)
    otp_uri = totp.provisioning_uri(name=username, issuer_name="Your App Name")
    qr = qrcode.make(otp_uri)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    qr_code_data = base64.b64encode(img_io.getvalue()).decode('utf-8')
    
    return render_template('setup_otp.html', qr_code_data=qr_code_data)
    # return send_file(img_io, mimetype='image/png')
    
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password'] 

        print(f"Attempting login for username: {username}")

        connection = sqlite3.connect('passwords.db')
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        connection.close()

        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('login'))

        print(f"Stored password hash: {user[3]}")
        print(f"Entered password: {password}")

        try:
            # Decrypt the stored password
            decrypted_password = cipher.decrypt(user[3].encode()).decode()
            print(f"Decrypted password: {decrypted_password}")

            # Compare the decrypted password with the entered password
            if decrypted_password == password:
                session['user_id'] = user[0]
                session['otp_secret'] = user[4]  # Ensure the correct OTP secret is stored in the session
                print(f"OTP secret: {user[4]}")
                flash('Login successful', 'success')
                return redirect(url_for('two_factor'))
            else:
                flash('Invalid username or password', 'danger')
        except Exception as e:
            print(f"Error decrypting password: {e}")
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/two_factor', methods=['POST', 'GET'])
def two_factor():
    if request.method == "POST":
        otp = request.form['otp']
        otp_secret = session.get('otp_secret')
        print(f"OTP secret from session: {otp_secret}")
        totp = pyotp.TOTP(otp_secret)
        if not otp_secret:
            flash('Invalid session. Please log in again.', 'danger')
            return redirect(url_for('login'))
        
        if totp.verify(otp):
            user_id = session.get('user_id')
            user = load_user(user_id)
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid OTP', 'danger')
    return render_template('two_factor.html')

@app.route('/delete_password/<int:id>', methods=['POST'])
@login_required
def delete_password_route(id):
    delete_password(id)
    flash('Password entry deleted successfully.', 'success')
    return redirect(url_for('view'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_id', None)
    session.pop('otp_secret', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/add', methods=['POST', 'GET'])
def add():
    if request.method == "POST":
        site = request.form['site']
        username = request.form['username']
        password = request.form['password']
        add_password(site, username, password)
        return redirect(url_for('index'))
    return render_template('add_password.html')

@app.route('/view', methods=['POST', 'GET'])
def view():
    encrypted = True
    revealed = False
    search_query = request.args.get('search')
    
    if request.method == "POST":
        passcode = request.form['passcode']
        if passcode == PASSCODE:
            encrypted = False
            revealed = True
        else:
            flash('Incorrect passcode', 'danger')
            
    if search_query:
        passwords = search_passwords(search_query, encrypted=encrypted)
    else:
        passwords = get_passwords(encrypted=encrypted)
    
    return render_template('view_passwords.html', passwords=passwords, encrypted=encrypted, revealed=revealed)

@app.route('/edit_password/<int:id>', methods=['POST'])
def edit_password(id):
    try:
        data = request.get_json()
        if not data or 'password' not in data:
            return jsonify({'success': False, 'error': 'Password not provided'}), 400
        
        new_password = data['password']
        print(f"New password: {new_password}")
        # Encrypt the new password
        encrypted_password = cipher.encrypt(new_password.encode())
        print(f"Encrypted password: {encrypted_password}")

        # Update the password in the database
        success = update_password_in_db(id, encrypted_password)
        print(f"Password update success: {success}")
        
        if success:
            return jsonify({'success': True})
        else:
            
            return jsonify({'success': False, 'error': 'Database update failed'}), 500
    except Exception as e:
        print(f"Error in edit_password route: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    
def update_password_in_db(id, new_password):
    try:
        print(f"Updating password for ID {id} with encrypted password: {new_password}")
        
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE passwords SET password = ? WHERE id = ?", (new_password, id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error updating password: {e}")
        return False
    
def is_valid_base32(s):
    try:
        base64.b32decode(s, casefold=True)
        return True
    except binascii.Error:
        return False


if __name__ == '__main__':
    load_user(1)
    # drop_users_table()
    # create_users_table()
    # drop_passwords_table()
    # create_passwords_table()
    app.run(debug=True, port=5001)