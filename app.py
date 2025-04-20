from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import os
import json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

def get_google_sheets_client():
    # Load credentials from environment variable instead of using a file
    credentials_json = os.getenv('GOOGLE_SHEETS_CREDENTIALS_JSON')
    
    if not credentials_json:
        raise ValueError("Google Sheets credentials not found in environment variables.")
    
    credentials_dict = json.loads(credentials_json)
    
    scope = ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive']
    credentials = ServiceAccountCredentials.from_json_keyfile_dict(credentials_dict, scope)
    return gspread.authorize(credentials)

try:
    client = get_google_sheets_client()
except Exception as e:
    app.logger.error(f"Google Sheets client error: {str(e)}")
    client = None

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    user_info = get_users_from_sheet().get(user_id)
    if user_info:
        return User(user_id, user_info["role"])
    return None

def get_users_from_sheet():
    try:
        sheet = client.open('Ganesh-Chaturthi-2025').worksheet('Users')
        records = sheet.get_all_records()
        return {row['Username']: {"password": row['PasswordHash'], "role": row['Role']} for row in records}
    except Exception as e:
        app.logger.error(f"Error loading users: {str(e)}")
        return {}

def update_user_password(username, new_password_hash):
    sheet = client.open('Ganesh-Chaturthi-2025').worksheet('Users')
    records = sheet.get_all_records()
    for idx, row in enumerate(records, start=2):  # 1-based index; row 1 is headers
        if row['Username'] == username:
            sheet.update_cell(idx, 2, new_password_hash)  # Column 2 = PasswordHash
            return True
    return False

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = get_users_from_sheet()

        if username in users and check_password_hash(users[username]["password"], password):
            user = User(username, users[username]["role"])
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', is_admin=current_user.role == 'admin')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        users = get_users_from_sheet()

        if current_user.id in users and check_password_hash(users[current_user.id]["password"], current):
            new_hash = generate_password_hash(new)
            update_user_password(current_user.id, new_hash)
            flash("Password updated successfully.")
        else:
            flash("Current password is incorrect.")
    return render_template('change_password.html')

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash("Access denied.")
        return redirect(url_for('dashboard'))

    sheet = client.open('Ganesh-Chaturthi-2025').worksheet('Users')

    if request.method == 'POST':
        action = request.form['action']
        username = request.form['username']
        role = request.form.get('role', 'user')
        if action == 'add':
            password_hash = generate_password_hash(request.form['password'])
            sheet.append_row([username, password_hash, role])
            flash(f"User {username} added.")
        elif action == 'delete':
            records = sheet.get_all_records()
            for idx, row in enumerate(records, start=2):
                if row['Username'] == username:
                    sheet.delete_rows(idx)
                    flash(f"User {username} deleted.")
                    break

    users = get_users_from_sheet()
    return render_template('manage_users.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)
