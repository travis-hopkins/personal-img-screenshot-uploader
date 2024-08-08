import threading
import os
import uuid
import time
import logging
from datetime import datetime
from flask import Flask, request, jsonify, send_file, redirect, url_for, flash, render_template, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from requests_oauthlib import OAuth2Session
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt

# Load environment variables from .env file
load_dotenv('/opt/screenshot-app/app/config.env')

# Initialize Flask app
app = Flask(__name__, static_folder='/opt/screenshot-app/static', template_folder='/opt/screenshot-app/templates')

# Secret key for sessions
app.secret_key = os.getenv('SECRET_KEY')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS') == 'True'
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')

# Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# OAuth configuration
client_id = os.getenv('OAUTH_CLIENT_ID')
client_secret = os.getenv('OAUTH_CLIENT_SECRET')
authorization_base_url = os.getenv('OAUTH_AUTHORIZATION_BASE_URL')
token_url = os.getenv('OAUTH_TOKEN_URL')
redirect_uri = os.getenv('OAUTH_REDIRECT_URI')

# Handle OAuth scope
oauth_scope = os.getenv('OAUTH_SCOPE')
if oauth_scope is None:
    app.logger.error('OAUTH_SCOPE environment variable is not set.')
    raise ValueError('OAUTH_SCOPE environment variable is not set.')
scope = oauth_scope.split(',')

UPLOAD_FOLDER = app.config['UPLOAD_FOLDER']
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

logging.basicConfig(level=logging.DEBUG)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)  # Allow NULL for password
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    registration_method = db.Column(db.String, nullable=True)
    login_method = db.Column(db.String, nullable=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_blocked = db.Column(db.Boolean, default=False, nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_id(self):
        return self.id
    

class Screenshot(db.Model):
    id = db.Column(db.String(36), primary_key=True)  # UUID for filename
    filename = db.Column(db.String(256), nullable=False)
    delete_on_view = db.Column(db.Boolean, default=False)
    delete_after = db.Column(db.Integer, nullable=True)  # Minutes
    created_at = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

# Load user for login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"success": False, "error": "Unauthorized"}), 401

# Custom Jinja2 filter for formatting datetime
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, float):
        value = datetime.fromtimestamp(value)
    return value.strftime(format)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            flash('All fields are required.')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists')
            return redirect(url_for('register'))
        
        # Hash the password before storing it
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Generate token
        token = serializer.dumps(email, salt='email-confirm-salt')

        # Send confirmation email
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('activate.html', confirm_url=confirm_url)
        msg = Message('Confirm Your Email', recipients=[email])
        msg.html = html
        mail.send(msg)

        flash('A confirmation email has been sent to your email address.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm-salt', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user.is_active:
        flash('Account already confirmed. Please login.')
    else:
        user.is_active = True
        db.session.commit()
        flash('You have confirmed your account. Thanks!')

    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if user.is_active:
                login_user(user)
                flash('Logged in successfully.')
                return redirect(url_for('index'))
            else:
                flash('Please confirm your email before logging in.')
        else:
            flash('Invalid credentials')

    return render_template('login.html')



@app.route('/login/google')
def login_google():
    google = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    authorization_url, state = google.authorization_url(authorization_base_url, access_type='offline', prompt='select_account')
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    try:
        # Initialize OAuth2Session with your client credentials and state
        google = OAuth2Session(client_id, state=session.get('oauth_state'), redirect_uri=redirect_uri)
        token = google.fetch_token(token_url, client_secret=client_secret, authorization_response=request.url)
        session['google_token'] = token

        # Fetch user info from Google
        user_info = google.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
        email = user_info.get('email')

        if not email:
            raise ValueError("No email found in user info")

        # Check if user exists in the database
        user = User.query.filter_by(email=email).first()

        # If user does not exist, create a new one
        if not user:
            user = User(
                email=email,
                password=None,  # Set password to None for OAuth users
                is_active=True,
                registration_method='Google',
                login_method='OAuth'
            )
            db.session.add(user)
            db.session.commit()

        # Check if the user is blocked
        if user.is_blocked:
            session['popup_message'] = 'Your account is blocked. Please contact support.'
            return redirect(url_for('blocked'))

        # Log in the user
        login_user(user)

        # Redirect to the home page or any other page
        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f"Error during OAuth callback: {str(e)}")
        return jsonify({"success": False, "error": f"Error during OAuth callback: {str(e)}"}), 500


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    app.logger.info("Received upload request")
    try:
        if 'file' not in request.files:
            app.logger.warning("No file part in the request")
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            app.logger.warning("No selected file")
            return jsonify({'error': 'No selected file'}), 400
        
        if file:
            filename = str(uuid.uuid4()) + '.png'
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            app.logger.info(f"File saved: {file_path}")

            # Get deleteAfter value and validate it
            delete_after_minutes = request.form.get('deleteAfter', type=int)
            allowed_values = {5, 10, 30, 60, 300, 1440, 10080}  # Allowed values in minutes

            if delete_after_minutes != 0 and delete_after_minutes not in allowed_values:
                app.logger.warning(f"Invalid delete after value: {delete_after_minutes}")
                return jsonify({'error': 'Invalid delete after value.'}), 400

            delete_on_view = request.form.get('deleteOnView') == 'true'
            app.logger.debug(f"Delete after: {delete_after_minutes} minutes, Delete on view: {delete_on_view}")

            screenshot = Screenshot(
                id=filename,
                filename=filename,
                delete_after=delete_after_minutes,
                delete_on_view=delete_on_view,
                created_at=time.time(),
                user_id=current_user.id
            )
            db.session.add(screenshot)
            db.session.commit()

            if delete_after_minutes > 0:
                app.logger.info(f"Setting up timed deletion for {filename} after {delete_after_minutes} minutes")
                threading.Timer(delete_after_minutes * 60, delete_file, args=(file_path,)).start()

            file_url = f"https://scr.travis-hopkins.com/screenshot/{filename}"
            app.logger.info(f"Generated file URL: {file_url}")

            # Pass the screenshot_uploaded flag to the template
            return jsonify({'filename': filename, 'url': file_url, 'screenshot_uploaded': True})
        
        app.logger.warning("No file uploaded")
        return jsonify({'error': 'No file uploaded'}), 400
    except Exception as e:
        app.logger.error(f"Error during file upload: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500



@app.route('/delete_screenshot/<filename>', methods=['POST'])
@login_required
def delete_screenshot(filename):
    try:
        screenshot = Screenshot.query.filter_by(filename=filename, user_id=current_user.id).first()
        if screenshot:
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.exists(file_path):
                os.remove(file_path)
            db.session.delete(screenshot)
            db.session.commit()
            app.logger.info(f"Screenshot {filename} deleted successfully.")
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Screenshot not found or permission denied'})
    except Exception as e:
        app.logger.error(f"Error during screenshot deletion: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


    # Redirect to the 'my_screenshots' page or any appropriate page
    return redirect(url_for('my_screenshots'))

@app.route('/screenshot/<filename>')
def view_file(filename):
    try:
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.isfile(file_path):
            app.logger.warning(f"File not found: {file_path}")
            return jsonify({'error': 'File not found'}), 404

        screenshot = Screenshot.query.filter_by(id=filename).first()
        if screenshot and screenshot.delete_on_view:
            db.session.delete(screenshot)
            db.session.commit()
            os.remove(file_path)
            app.logger.info(f"File {filename} deleted after view")
        
        return send_file(file_path)
    except Exception as e:
        app.logger.error(f"Error viewing file {filename}: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/my-screenshots')
@login_required
def my_screenshots():
    try:
        screenshots = Screenshot.query.filter_by(user_id=current_user.id).all()
        return render_template('my-screenshots.html', screenshots=screenshots)
    except Exception as e:
        app.logger.error(f"Error retrieving user screenshots: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

def delete_file(file_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            app.logger.info(f"File {file_path} deleted after timer")
    except Exception as e:
        app.logger.error(f"Error deleting file {file_path}: {str(e)}", exc_info=True)

@app.route('/clear_database', methods=['POST'])
@login_required
def clear_database():
    try:
        # Drop all tables in the database
        db.drop_all()
        # Create all tables again
        db.create_all()
        flash('Database cleared and reset successfully.')
    except Exception as e:
        db.session.rollback()
        flash(f'Error clearing the database: {str(e)}')

    return redirect(url_for('index'))

@app.route('/users')
@login_required
def users():
    # Ensure the current user is an admin or authorized to view this page
    if not current_user.is_admin:  # Replace with your actual authorization check
        return redirect(url_for('index'))

    users = User.query.all()  # Fetch all users from the database
    return render_template('users.html', users=users)

@app.route('/set_admin/<int:user_id>', methods=['POST'])
@login_required
def set_admin(user_id):
    # Ensure only admins can perform this action
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    user = User.query.get(user_id)
    if user:
        user.is_admin = True
        db.session.commit()
        return redirect(url_for('users'))
    return jsonify({"success": False, "error": "User not found"}), 404

@app.route('/remove_admin/<int:user_id>', methods=['POST'])
@login_required
def remove_admin(user_id):
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    user = User.query.get(user_id)
    if user:
        user.is_admin = False
        db.session.commit()
        flash('User has been removed from admin privileges.')
        return redirect(url_for('users'))
    return jsonify({"success": False, "error": "User not found"}), 404

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to delete users.', 'danger')
        return redirect(url_for('index'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('users'))

@app.route('/block_user/<int:user_id>', methods=['POST'])
@login_required
def block_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.is_blocked = True
        db.session.commit()
    return redirect(url_for('users'))

@app.route('/unblock_user/<int:user_id>', methods=['POST'])
@login_required
def unblock_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.is_blocked = False
        db.session.commit()
    return redirect(url_for('users'))

@app.route('/blocked')
def blocked():
    message = session.pop('popup_message', None)
    return render_template('blocked.html', message=message)



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')