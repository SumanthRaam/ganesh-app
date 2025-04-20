from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime
import os
import json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

def get_google_sheets_client():
    """Get an authorized Google Sheets client using credentials from environment variables"""
    try:
        # Get credentials from environment variable
        credentials_json = os.getenv('GOOGLE_SHEETS_CREDENTIALS')
        if not credentials_json:
            raise ValueError("Google Sheets credentials not found in environment variables")
        
        # Parse the JSON string
        credentials_dict = json.loads(credentials_json)
        
        # Create credentials object
        scope = ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive']
        credentials = ServiceAccountCredentials.from_json_keyfile_dict(credentials_dict, scope)
        
        # Authorize the client
        return gspread.authorize(credentials)
    except Exception as e:
        app.logger.error(f"Error initializing Google Sheets client: {str(e)}")
        raise

# Initialize Google Sheets client
try:
    client = get_google_sheets_client()
except Exception as e:
    app.logger.error(f"Failed to initialize Google Sheets client: {str(e)}")
    client = None

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Simple user class
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Hardcoded user for demo (in production, use a proper database)
USERS = {
    'admin': generate_password_hash('admin123')
}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and check_password_hash(USERS[username], password):
            user = User(username)
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    if not client:
        flash('Google Sheets service is not available. Please contact administrator.')
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        try:
            # Get form data
            name = request.form.get('name')
            address = request.form.get('address')
            phone = request.form.get('phone')
            amount = request.form.get('amount')
            date = request.form.get('date')
            
            # Open the Google Sheet
            sheet = client.open('Ganesh-Chaturthi-2025').sheet1
            
            # Check if phone number already exists
            phone_numbers = sheet.col_values(3)  # Assuming phone is in column 3
            if phone in phone_numbers:
                flash('Phone number already exists!')
                return redirect(url_for('submit'))
            
            # Append new row
            sheet.append_row([name, address, phone, amount, date, datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            flash('Data submitted successfully!')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            app.logger.error(f"Error submitting data: {str(e)}")
            flash(f'Error: {str(e)}')
            return redirect(url_for('submit'))
    
    return render_template('submit.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if not client:
        flash('Google Sheets service is not available. Please contact administrator.')
        return redirect(url_for('home'))
        
    try:
        sheet = client.open('Ganesh-Chaturthi-2025').sheet1
        records = sheet.get_all_records()
        # Sort by date (assuming last column is timestamp)
        records.sort(key=lambda x: x['Timestamp'], reverse=True)
        return render_template('dashboard.html', records=records)
    except Exception as e:
        app.logger.error(f"Error fetching dashboard data: {str(e)}")
        flash(f'Error: {str(e)}')
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True) 