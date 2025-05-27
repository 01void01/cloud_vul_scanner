import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from app.routes import routes_bp

app = Flask(__name__, template_folder='app/templates')

# Use an environment variable for the secret key in production.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-this')
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes session timeout

# Secure cookie settings 
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'True') == 'True'
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access the vulnerability scanner.'
login_manager.login_message_category = 'info'
login_manager.session_protection = "strong"

# In-memory user storage
users = {
    'admin': {
        'username': 'admin',
        'password': bcrypt.generate_password_hash('admin123').decode('utf-8'),
        'email': 'admin@company.com'
    },
    'scanner': {
        'username': 'scanner',
        'password': bcrypt.generate_password_hash('scan123').decode('utf-8'),
        'email': 'scanner@company.com'
    }
}

class User(UserMixin):
    def __init__(self, username, email):
        self.id = username
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(users[user_id]['username'], users[user_id].get('email', ''))
    return None

# -----------------------------
# Authentication Routes
# -----------------------------

@app.route('/')
def index():
    """Default route starts at login."""
    return redirect(url_for('login'))

@app.route('/force-logout')
def force_logout():
    if current_user.is_authenticated:
        logout_user()
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Redirect already authenticated users to the dashboard.
    if current_user.is_authenticated:
        return redirect(url_for('routes.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        remember = (request.form.get('remember') == 'on')

        # Ensure both fields are provided.
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('login.html')

        if len(username) < 4 or len(password) < 4:
            flash('Username and password must be at least 4 characters long.', 'danger')
            return render_template('login.html')

        # Verify credentials.
        if username in users and bcrypt.check_password_hash(users[username]['password'], password):
            user = User(users[username]['username'], users[username].get('email', ''))
            login_user(user, remember=remember)
            session.permanent = True  # Ensure session uses the PERMANENT_SESSION_LIFETIME.
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('routes.dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Redirect if already authenticated.
    if current_user.is_authenticated:
        return redirect(url_for('routes.dashboard'))
    
    # Clear session for fresh registration.
    session.clear()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        # Validate fields.
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if len(username) < 4 or len(password) < 4:
            flash('Username and password must be at least 4 characters long.', 'danger')
            return render_template('register.html')

        if len(email) < 6 or '@' not in email:
            flash('Please enter a valid email address.', 'danger')
            return render_template('register.html')

        if username in users:
            flash('Username already exists. Choose a different one.', 'danger')
            return render_template('register.html')

        # Store the new user with a hashed password.
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users[username] = {
            'username': username,
            'password': hashed_password,
            'email': email
        }
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Register the routes blueprint.
app.register_blueprint(routes_bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
else:
    with app.app_context():
        session.clear()
