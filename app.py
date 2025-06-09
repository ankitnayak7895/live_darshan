from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify,render_template_string,make_response,send_file,abort
import uuid
import re
import bcrypt
from datetime import datetime, timedelta
import mysql.connector
from mysql.connector import MySQLConnection,connect
from mysql.connector.cursor import MySQLCursorDict
from io import BytesIO
import os
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from urllib.parse import urlparse, parse_qs,urljoin
from functools import wraps
import logging
from werkzeug.exceptions import HTTPException
from flask_mail import Mail,Message
from flask_login import LoginManager,current_user
from db.mysqldb import register_user, authenticate_user, authenticate_admin, update_password,get_db_connection
from flask_login import UserMixin,login_user,logout_user,login_required
from xhtml2pdf import pisa
from weasyprint import HTML
import base64
import pdfkit
from werkzeug.routing import BaseConverter
from reportlab.pdfgen import canvas
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import openai


# =============== uuid base converter================================
class UUIDConverter(BaseConverter):
    def to_python(self, value):
        try:
            return uuid.UUID(value)
        except ValueError:
            abort(404)

    def to_url(self, value):
        return str(value)

# =================== App Configuration ===================
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.url_map.converters['uuid'] = UUIDConverter

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)  # Ensure debug logs show

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # specify your login route


UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config['OPENAI_API_KEY'] = "your-openai-key"
# =======================Test-UUID=====================================
@app.route('/test/<uuid:test_id>')
def test_uuid(test_id):
    return f"Received UUID: {test_id}, Type: {type(test_id)}"

# Make it available to templates
@app.context_processor
def inject_template_helpers():
    return dict(check_login_status=check_login_status)

@app.before_request
def update_user_last_activity():
    if 'user_id' in session and 'session_token' in session:
        try:
            conn = get_mysql_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE user_sessions 
                SET last_activity = CURRENT_TIMESTAMP 
                WHERE user_id = %s AND session_token = %s
            """, (session['user_id'], session['session_token']))
            conn.commit()
        except Exception as e:
            print(f"[ERROR] update_user_last_activity: {e}")
        finally:
            cursor.close()
            conn.close()



@app.context_processor
def inject_user_status():
    is_logged_in = False
    current_username = None
    current_user_id = None

    if 'user_id' in session and 'session_token' in session:
        conn = None
        cursor = None
        try:
            conn = get_mysql_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("""
                SELECT u.username, us.is_logged_in
                FROM user_sessions us
                JOIN users u ON us.user_id = u.id
                WHERE us.user_id = %s 
                  AND us.session_token = %s
                  AND us.last_activity > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            """, (session['user_id'], session['session_token']))

            result = cursor.fetchone()
            if result and result['is_logged_in']:
                is_logged_in = True
                current_username = result['username']
                current_user_id = session['user_id']

        except Exception as e:
            print(f"[ERROR] inject_user_status: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return {
        'is_logged_in': is_logged_in,
        'current_username': current_username,
        'current_user_id': current_user_id
    }

# ========================Connection health=======================================
def check_connection_health():
    try:
        with db_cursor() as cursor:
            cursor.execute("SELECT 1")
            return cursor.fetchone() is not None
    except Exception:
        return False


@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    return jsonify({
        "error": "An internal server error occurred",
        "message": str(e)
    }), 500
# ============================= Email Setup =============================================
import os
from flask_mail import Mail, Message

# Load credentials securely
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'ankitnayak7895@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'sogpyytnwzgrgxgv')
app.config['MAIL_DEFAULT_SENDER'] = ('Live Darshan', app.config['MAIL_USERNAME'])

mail = Mail(app)

# =========================== Send Confirmation Email ====================================
def send_order_confirmation_email(user_email, user_fullname, order):
    try:
        subject = "Order Confirmation - Divine Access"

        html_content = render_template(
            'order_confirmation_email.html',
            order=order,
            user_fullname=user_fullname
        )

        msg = Message(
            subject=subject,
            recipients=[user_email],
            html=html_content
        )

        mail.send(msg)
        app.logger.info(f"✅ Order confirmation email sent to {user_email}")

    except Exception as e:
        app.logger.error(f"❌ Failed to send order confirmation email: {e}", exc_info=True)

@app.route('/test-email')
def test_email():
    fake_order = {
        'order_id': 'TEST123',
        'product_name': 'Test Product',
        'quantity': 1,
        'total_price': 999,
        'address': '123 Demo Street',
        'city': 'Testville',
        'pincode': '000000'
    }
    send_order_confirmation_email('your-email@example.com', 'Test User', fake_order)
    return "Test email sent (check logs)"


# =====================================Logging===========================================

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =================== MySQL Connection ===================
def get_mysql_connection():
    try:
        conn = mysql.connector.connect(
            host=os.getenv('MYSQL_HOST', 'localhost'),      # <- env var name here
            user=os.getenv('MYSQL_USER', 'root'),           # <- env var name here
            password=os.getenv('MYSQL_PASSWORD', 'Omm@12'),       # <- env var name here
            database=os.getenv('MYSQL_DATABASE', 'web_portal'),       # <- env var name here
            autocommit=False,
            buffered=False,
            consume_results=True
        )
        logger.info("Database connection successful")
        return conn
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return None
   
# ===============================context==============================================
from contextlib import contextmanager
@contextmanager
def db_cursor():
    conn = None
    cursor = None
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        yield cursor
        if conn and conn.unread_result is False:  # Avoid commit if there's unread result
            conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Database error in db_cursor: {e}")
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# Example usage:
@app.route("/example")
def example():
    with get_mysql_connection() as cursor:
        cursor.execute("SELECT * FROM some_table")
        results = cursor.fetchall()
    return jsonify(results)



# ========================Error Handler===================================================
@app.errorhandler(Exception)
def handle_exception(e):
    # Log the error
    logger.error(f"An error occurred: {str(e)}")
    
    # Handle HTTP exceptions
    if isinstance(e, HTTPException):
        return e
    
    # Return a generic error response
    return jsonify({
        "success": False,
        "error": "An internal server error occurred"
    }), 500

# ===============================Admin/User-Model==============================================

class User(UserMixin):
    def __init__(self, user_dict):
        self.id = user_dict.get('id')
        self.username = user_dict.get('username')
        self.email = user_dict.get('email')
        self.created_at = user_dict.get('created_at')
        self.role = user_dict.get('role', 'user')  # Optional, defaults to 'user'
        self.firstname = user_dict.get('firstname')  # 🔥 Add this
        self.lastname = user_dict.get('lastname') 
        self.mobilenumber = user_dict.get('mobilenumber')  # optional

    def get_id(self):
        return str(self.id)
    
@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            (SELECT id, username, firstname, lastname, email, 
                    mobilenumber, password_hash AS password, 
                    created_at, 'user' AS role 
             FROM users WHERE id = %s)
            UNION
            (SELECT id, username, NULL AS firstname, NULL AS lastname, 
                    email, NULL AS mobilenumber, password AS password, 
                    created_at, 'admin' AS role 
             FROM admins WHERE id = %s)
        """, (user_id, user_id))

        user_data = cursor.fetchone()
        if user_data:
            return User(user_data)

    except Exception as e:
        app.logger.error(f"[load_user] Error loading user: {e}")
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

    return None

        
@app.route('/protected-route')
@login_required  # Now using Flask-Login's decorator
def protected_route():
    # current_user will be available here
    return f"Hello {current_user.username}"

def is_user_logged_in(user_id, session_token):
    try:
        with db_cursor() as cursor:
            cursor.execute("""
                SELECT is_logged_in 
                FROM user_sessions 
                WHERE user_id = %s 
                AND session_token = %s 
                AND last_activity > DATE_SUB(NOW(), INTERVAL 1 HOUR)
                AND expires_at > NOW()
            """, (user_id, session_token))
            result = cursor.fetchone()
            return bool(result and result.get('is_logged_in'))
    except Exception as e:
        logger.error(f"Error checking login status: {e}")
        return False


@app.route('/debug/user/<int:user_id>')
def debug_user(user_id):
    return render_template_string("""
        <h2>User Debug Information</h2>
        <p><strong>User ID:</strong> {{ user_id }}</p>
        <p><strong>Status:</strong> {{ 'Logged In' if check_login_status(user_id) else 'Logged Out' }}</p>
        <p><strong>Last Activity:</strong> {{ get_last_activity(user_id) or 'Never' }}</p>
    """, user_id=user_id)
    
    
# =================Improved Add Items================================================
def validate_admin_session():
    if 'admin_id' not in session:
        logger.warning("Unauthorized admin access attempt")
        return jsonify({"success": False, "error": "Unauthorized"}), 403
    return None

def handle_database_operation(query, params, success_message):
    conn = None
    cursor = None
    try:
        conn = get_mysql_connection()
        if not conn:
            return jsonify({"success": False, "error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        return jsonify({
            "success": True,
            "message": success_message,
            "id": cursor.lastrowid
        })
    except Exception as e:
        logger.error(f"Database operation failed: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
        
        
        
# =========================Unified Add Item Route===================================

@app.route('/admin/add_item/<item_type>', methods=['POST'])
def add_item(item_type):
    # Validate admin session
    auth_error = validate_admin_session()
    if auth_error:
        return auth_error
    
    # Get data based on content type
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()
    
    logger.info(f"Adding {item_type} item with data: {data}")
    
    try:
        if item_type == 'products':
            # Validate product data
            if not all(data.get(k) for k in ['name', 'price']):
                return jsonify({"success": False, "error": "Missing required fields"}), 400
            
            try:
                price = float(data['price'])
            except ValueError:
                return jsonify({"success": False, "error": "Invalid price format"}), 400
            
            return handle_database_operation(
                "INSERT INTO products (name, description, price, image_url) VALUES (%s, %s, %s, %s)",
                (data['name'], data.get('description', ''), price, data.get('image_url', '')),
                "Product added successfully"
            )
            
        elif item_type == 'images':
            # Handle file upload if present
            if 'file' in request.files:
                file = request.files['file']
                if file.filename != '':
                    filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    data['image_url'] = f"/static/uploads/{filename}"
            
            return handle_database_operation(
                "INSERT INTO images (title, url, description) VALUES (%s, %s, %s)",
                (data['title'], data.get('image_url', data.get('url', '')), data.get('description', '')),
                "Image added successfully"
            )
            
        elif item_type == 'videos':
            # Extract YouTube ID
            video_id = extract_video_id(data['link'])
            if not video_id:
                return jsonify({"success": False, "error": "Invalid YouTube URL"}), 400
                
            return handle_database_operation(
                "INSERT INTO videos (title, youtube_link) VALUES (%s, %s)",
                (data['title'], video_id),
                "Video added successfully"
            )
            
        else:
            return jsonify({"success": False, "error": "Invalid item type"}), 400
            
    except KeyError as e:
        logger.error(f"Missing key in data: {str(e)}")
        return jsonify({"success": False, "error": f"Missing required field: {str(e)}"}), 400

# =================== Utility Functions ===================
def is_safe_url(target):
    """Check if a URL is safe to redirect to (prevent open redirects)"""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        session_token = session.get('session_token')

        # If no session info in Flask session, try from cookie (for remember me)
        if not user_id or not session_token:
            session_token = request.cookies.get('session_token')
            if session_token:
                # Validate token from DB and update Flask session if valid
                conn = get_mysql_connection()
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT user_id, expires_at, is_logged_in FROM user_sessions 
                    WHERE session_token = %s
                """, (session_token,))
                user_session = cursor.fetchone()
                cursor.close()
                conn.close()

                if user_session and user_session['is_logged_in'] == 1 and user_session['expires_at'] > datetime.utcnow():
                    # Valid session, set Flask session variables
                    session['user_id'] = user_session['user_id']
                    session['session_token'] = session_token
                    user_id = user_session['user_id']
                else:
                    # Invalid or expired session token
                    return redirect(url_for('login', next=request.url))
            else:
                # No session token found anywhere
                return redirect(url_for('login', next=request.url))
        else:
            # Validate existing session from Flask session
            conn = get_mysql_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT expires_at, is_logged_in FROM user_sessions 
                WHERE user_id = %s AND session_token = %s
            """, (user_id, session_token))
            user_session = cursor.fetchone()
            cursor.close()
            conn.close()

            if not user_session or user_session['is_logged_in'] != 1 or user_session['expires_at'] <= datetime.utcnow():
                # Session invalid or expired
                return redirect(url_for('login', next=request.url))

        return f(*args, **kwargs)

    return decorated_function
# ======================================================================
def init_database():
    try:
        with db_cursor() as cursor:
            # Create user_sessions table if not exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    user_id INT PRIMARY KEY,
                    is_logged_in BOOLEAN DEFAULT FALSE,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            # Check and add columns if needed
            cursor.execute("SHOW TABLES LIKE 'products'")
            if cursor.fetchone():
                cursor.execute("SHOW COLUMNS FROM products LIKE 'buy_now_enabled'")
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE products ADD COLUMN buy_now_enabled TINYINT(1) DEFAULT 1")
                
                cursor.execute("SHOW COLUMNS FROM products LIKE 'buy_now_text'")
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE products ADD COLUMN buy_now_text VARCHAR(50) DEFAULT 'Buy Now'")
        
        logger.info("Database tables verified/created successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

init_database()
# =================== Template Filters =====================
from urllib.parse import urlparse, parse_qs

def youtube_embed(link):
    try:
        url = urlparse(link)
        
        # Handle standard YouTube URLs
        if 'youtube.com' in url.netloc:
            query = parse_qs(url.query)
            return query.get('v', [None])[0]
        
        # Handle shortened youtu.be URLs
        elif 'youtu.be' in url.netloc:
            return url.path.lstrip('/')
        
        # Handle direct video ID
        elif len(link) == 11:
            return link
        
    except Exception as e:
        # Optional: log the exception for debugging
        pass

    return None


@app.template_filter('youtube_embed')
def youtube_embed_filter(link):
    return youtube_embed(link)

# =================chat-bot=====================================================
# see last

# ===================== Home Page ===========================
@app.route("/")
def home():
    dashboards = []
    videos = []
    images = []
    user_name = session.get('user_name')  # Get username from session if logged in

    try:
        # Fetch dashboards
        with db_cursor() as cursor:
            cursor.execute("SELECT * FROM dashboards_items ORDER BY created_at DESC LIMIT 6")
            dashboards = cursor.fetchall()

        # Fetch videos
        with db_cursor() as cursor:
            cursor.execute("SELECT title, link FROM youtube_videos ORDER BY created_at DESC")
            videos = cursor.fetchall()

        # Fetch images
        with db_cursor() as cursor:
            cursor.execute("SELECT * FROM images ORDER BY created_at DESC")
            images = cursor.fetchall()

    except Exception as e:
        flash("Error loading homepage content.", "danger")
        logger.error(f"DB Error in home route: {e}")

    return render_template(
        "home.html",
        dashboards=dashboards,
        videos=videos,
        images=images,
        user_name=user_name
    )



# ===========================================================================
@app.teardown_request
def teardown_request(exception):
    # This will run after each request to clean up database connections
    pass  # The individual routes should handle their own cleanup

# ===================== Registration ========================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data ={
            "username": request.form.get("username", "").strip(),
            "firstname": request.form.get("firstName", "").strip(),   # matches name="firstName"
            "lastname": request.form.get("lastName", "").strip(),     # matches name="lastName"
            "email": request.form.get("email", "").strip(),
            "mobile": request.form.get("mobileNumber", "").strip(),   # matches name="mobileNumber"
            "password": request.form.get("password", "").strip()
        }
        
        
        # Check if any field is empty
        if not all(data.values()):
            flash("All fields are required.", "warning")
            return redirect(url_for("register"))

        if not re.match(r'^[a-zA-Z0-9]+$', data["username"]):
            flash("Username must be alphanumeric.", "warning")
            return redirect(url_for("register"))
        
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', data["email"]):
            flash("Invalid email address.", "warning")
            return redirect(url_for("register"))
        if not re.match(r'^[6-9]\d{9}$', data["mobile"]):
            flash("Invalid mobile number.", "warning")
            return redirect(url_for("register"))
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,16}$', data["password"]):
            flash("Password must be 8–16 chars, incl. uppercase, lowercase, digit, and symbol.", "warning")
            return redirect(url_for("register"))

        try:
            hashed_pw = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()).decode()
            
            register_user(
                data["username"],
                data["firstname"],
                data["lastname"],
                data["email"],
                data["mobile"],
                hashed_pw
            )
            
            msg = Message(
                  subject="Welcome to Live Darshan – Registration Successful!",
                  recipients=[data["email"]],
                   body=f"""Dear {data['firstname']},

Your account with username '{data['username']}' has been successfully registered.

Thank you for joining Live Darshan!

Best regards,
Live Darshan Team"""
)

            mail.send(msg)
            
            flash("Registration successful!", "success")
            return redirect(url_for("login"))
        
        except Exception as e:
            flash(str(e), "danger")
            return redirect(url_for("register"))

    return render_template("register.html")

from mysql.connector import Error

def register_user(username, firstname, lastname, email, mobile, hashed_password):
    connection = None
    cursor = None
    try:
        connection = get_mysql_connection()
        if connection:
            cursor = connection.cursor()
            query = """
                INSERT INTO users (username, firstname, lastname, email, mobilenumber, password_hash)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (username, firstname, lastname, email, mobile, hashed_password))
            connection.commit()
    except Error as e:
        print(f"[DB ERROR] Registration failed: {e}")
        raise
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# ===================== Login ========================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        try:
            with get_mysql_connection() as conn:
                with conn.cursor(dictionary=True) as cursor:
                    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                    user = cursor.fetchone()

            if user:
                stored_hash = user['password_hash'].encode('utf-8')
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                    session_token = str(uuid.uuid4())
                    expires_at = datetime.utcnow() + (timedelta(days=30) if remember else timedelta(hours=1))

                    with get_mysql_connection() as conn:
                        with conn.cursor() as cursor:
                            cursor.execute("""
                                INSERT INTO user_sessions (user_id, session_token, is_logged_in, last_activity, expires_at) 
                                VALUES (%s, %s, 1, NOW(), %s)
                                ON DUPLICATE KEY UPDATE 
                                    session_token = VALUES(session_token),
                                    is_logged_in = 1,
                                    last_activity = NOW(),
                                    expires_at = VALUES(expires_at)
                            """, (user['id'], session_token, expires_at))
                        conn.commit()

                    # ✅ Flask-Login login
                    user_obj = User(user)  # Assuming your User class accepts dict
                    login_user(user_obj, remember=remember)

                    # ✅ Still save in session if needed
                    session['user_id'] = user['id']
                    session['session_token'] = session_token
                    session['username'] = user['username']

                    next_url = session.pop('next_url', url_for('ecommerce'))
                    resp = make_response(redirect(next_url))

                    max_age = 30 * 24 * 3600 if remember else None
                    resp.set_cookie('session_token', session_token, max_age=max_age, httponly=True, samesite='Lax')

                    return resp
        except Exception as e:
            print(f"Login error: {e}")
            flash('Something went wrong. Please try again.', 'danger')

        flash('Invalid username or password', 'danger')
        return render_template('login.html')

    next_url = request.args.get('next')
    if next_url:
        session['next_url'] = next_url
    return render_template('login.html')

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])

@app.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id')
    session_token = session.get('session_token')

    try:
        if user_id and session_token:
            with get_mysql_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE user_sessions 
                        SET is_logged_in = 0 
                        WHERE user_id = %s AND session_token = %s
                    """, (user_id, session_token))
                conn.commit()
    except Exception as e:
        # Log in real app
        print(f"Logout error: {e}")

    # ✅ Important: Log out from Flask-Login
    logout_user()

    # ✅ Clear session data
    session.clear()
    flash("Logged out successfully", "success")

    # ✅ Remove session_token cookie
    resp = make_response(redirect(url_for('ecommerce')))
    resp.set_cookie('session_token', '', expires=0, httponly=True, samesite='Lax')
    return resp

@app.before_request
def update_last_activity():
    if current_user.is_authenticated:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE user_sessions 
            SET last_activity = CURRENT_TIMESTAMP 
            WHERE user_id = %s AND is_logged_in = TRUE
        """, (current_user.id,))
        conn.commit()
        cursor.close()
        conn.close()
        

@app.route('/check-login-status')
def check_login_status_route():
    user_id = session.get('user_id')
    session_token = session.get('session_token')
    username = session.get('username')  # ✅ Also get the username from session

    if not user_id or not session_token:
        return jsonify({'is_logged_in': False, 'username': None})

    is_logged_in = check_user_login_status(user_id, session_token)

    return jsonify({
        'is_logged_in': is_logged_in,
        'username': username if is_logged_in else None  # ✅ Send username if logged in
    })


def check_user_login_status(user_id, session_token):
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT is_logged_in 
            FROM user_sessions 
            WHERE user_id = %s 
            AND session_token = %s
            AND last_activity > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        """, (user_id, session_token))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return bool(result and result['is_logged_in'])
    except Exception as e:
        logger.error(f"Error in check_user_login_status: {e}")
        return False


@app.route('/set-next-url', methods=['POST'])
def set_next_url():
    if request.is_json:
        next_url = request.json.get('next_url')
        if next_url and is_safe_url(next_url):
            session['next_url'] = next_url
            return jsonify({'success': True})
    return jsonify({'success': False}), 400

def check_login_status():
    user_id = session.get('user_id')
    session_token = session.get('session_token')
    if not user_id or not session_token:
        return False
    return check_user_login_status(user_id, session_token)


@app.context_processor
def inject_login_status_checker():
    return dict(check_login_status=check_login_status)

#========================== This is the decorator i need to change =============================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session and database
        if 'user_id' not in session or 'session_token' not in session:
            session['next_url'] = request.url
            return redirect(url_for('login', next=request.url))
        
        # Verify against database
        with db_cursor() as cursor:
            cursor.execute("""
                SELECT is_logged_in 
                FROM user_sessions 
                WHERE user_id = %s 
                AND session_token = %s
                AND last_activity > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            """, (session['user_id'], session['session_token']))
            result = cursor.fetchone()
            
            if not result or not result['is_logged_in']:
                session.pop('user_id', None)
                session.pop('session_token', None)
                session['next_url'] = request.url
                return redirect(url_for('login', next=request.url))
            
            # Update last activity
            cursor.execute("""
                UPDATE user_sessions 
                SET last_activity = CURRENT_TIMESTAMP 
                WHERE user_id = %s
            """, (session['user_id'],))
        
        return f(*args, **kwargs)
    return decorated_function

# ===================== Admin Login =====================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        admin = authenticate_admin(request.form["username"], request.form["password"])
        if admin:
            session["admin_id"], session["admin_username"] = admin[0], admin[1]
            return redirect(url_for("admin_dashboard"))
        flash("Invalid admin credentials.", "danger")
    return render_template("admin_login.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    if "admin_id" not in session:
        flash("Admin access required.", "danger")
        return redirect(url_for("admin_login"))
    return render_template("admin_dashboard.html", admin=session["admin_username"])

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_id", None)
    session.pop("admin_username", None)
    flash("Admin logged out.", "info")
    return redirect(url_for("home"))


# ===================== Dashboard Items ===================
@app.route("/admin/add_dashboards_item", methods=["POST"])
def add_dashboard_item():
    if "admin_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    data = request.get_json()
    if not all(data.get(k) for k in ["title", "link", "description", "image_url"]):
        return jsonify({"success": False, "error": "Missing fields"}), 400

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO dashboards_items (title, link, description, image_url, created_at) VALUES (%s, %s, %s, %s, NOW())",
            (data["title"], data["link"], data["description"], data["image_url"])
        )
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route("/admin/get_dashboards")
def get_dashboards():
    if "admin_id" not in session:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM dashboards_items ORDER BY created_at DESC")
        dashboards = cursor.fetchall()
        return jsonify({"dashboards": dashboards})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route("/admin/delete_dashboard/<int:item_id>", methods=["DELETE"])
def delete_dashboard(item_id):
    if "admin_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM dashboards_items WHERE id = %s", (item_id,))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# ===================== Live YouTube ===================
# ========== API for JavaScript-based YouTube Video Handling ==========

@app.route("/admin/add_youtube_item", methods=["POST"])
def add_youtube_item():
    if "admin_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    data = request.get_json()
    title=data.get("title")
    link = data.get("link")

    if not link or not title:
        return jsonify({"success": False, "error": "Missing YouTube link or titile"}), 400

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO youtube_videos (title,link, created_at) VALUES (%s,%s, NOW())", (title,link,))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route("/admin/get_youtube")
def get_youtube():
    if "admin_id" not in session:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id,title,link FROM youtube_videos ORDER BY created_at DESC")
        videos = cursor.fetchall()
        print(videos)
        return jsonify({"youtube": videos})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route("/admin/delete_youtube_item/<int:item_id>", methods=["DELETE"])
def delete_youtube_item(item_id):
    if "admin_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM youtube_videos WHERE id = %s", (item_id,))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()



# ===================== Image Uploads ===================
@app.route("/admin/add_images_item", methods=["POST"])
def add_images_item():
    if "admin_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    data = request.get_json()
    title = data.get("title")
    description = data.get("description")
    image_url= data.get("image_url", "")

    if not title or not description or not image_url:
        return jsonify({"success": False, "error": "Missing fields"}), 400

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO images (title, url, description, created_at) VALUES (%s, %s, %s, NOW())",
            (title, image_url, description)
        )
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route("/upload_image", methods=["POST"])
def upload_image():
    if "admin_id" not in session:
        flash("Admin access required.", "danger")
        return redirect(url_for("admin_dashboard"))

    title = request.form.get("title")
    description = request.form.get("description")
    file = request.files.get("file")

    if not title or not file:
        flash("Title and file are required.", "warning")
        return redirect(url_for("admin_dashboard"))

    filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)
    image_url = f"/static/uploads/{filename}"

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO images (title, url, description, created_at) VALUES (%s, %s, %s, NOW())",
            (title, image_url, description)
        )
        conn.commit()
        flash("Image uploaded successfully!", "success")
    except Exception as e:
        flash(f"MySQL Error: {e}", "danger")
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

    return redirect(url_for("admin_dashboard"))

@app.route("/admin/get_images")
def get_images():
    if "admin_id" not in session:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM images ORDER BY created_at DESC")
        images = cursor.fetchall()
        return jsonify({"images": images})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route("/admin/delete_image_item/<int:item_id>", methods=["DELETE"])
def delete_image_item(item_id):
    try:
        # Replace with actual database logic to delete the image by ID
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM images WHERE id = %s", (item_id,))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500



# =================== Static Pages ===================
@app.route("/contact_us")
def contact_us():
    return render_template("contact_us.html")


# ===============================For Inbox====================================
# ===============================For Inbox====================================
@app.route('/inbox', methods=['GET'])  # Only allow GET requests
def inbox():
    if request.method == 'POST':
        return jsonify(success=False, error="Message submission not allowed here"), 403
    
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT section, message, created_at 
            FROM web_portal.inbox 
            ORDER BY created_at DESC
        """)
        messages = cursor.fetchall()
        return render_template("inbox.html", messages=messages)
        
    except Exception as e:
        app.logger.error(f"Inbox error: {str(e)}")
        return render_template("inbox.html", messages=[])
        
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
        
@app.route('/admin/get_inbox')
def get_inbox_json():
    if "admin_id" not in session:
        return jsonify(success=False, error="Unauthorized"), 403
    conn=None
    cursor=None
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, message, section FROM web_portal.inbox ORDER BY created_at DESC")
        messages = cursor.fetchall()
        return jsonify(success=True,inbox=messages)
    except Exception as e:
        return jsonify(success=False, error=str(e)),500
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()
        
@app.route('/admin/add_inbox_item', methods=['POST'])
def add_inbox_json():
    # Authentication check
    if "admin_id" not in session:
        return jsonify(success=False, error="Unauthorized"), 403
    
    # Data validation
    data = request.get_json()
    if not data:
        return jsonify(success=False, error="No data received"), 400
    
    # Field extraction with fallbacks
    message = data.get("message", "").strip() or data.get("description", "").strip()
    section = data.get("section", "").strip() or data.get("title", "").strip()
    
    # Validation
    if not message:
        return jsonify(success=False, error="Message content is required"), 400
    if not section:
        return jsonify(success=False, error="Section is required"), 400
    
    # Database connection
    conn = None
    cursor = None
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        # Insert message
        cursor.execute(
            "INSERT INTO web_portal.inbox (message, section) VALUES (%s, %s)",
            (message, section)
        )
        conn.commit()
        
        # Get the inserted ID
        new_id = cursor.lastrowid
        
        return jsonify(
            success=True,
            message="Message added successfully",
            id=new_id
        )
        
    except Exception as e:
        app.logger.error(f"Failed to add inbox item: {str(e)}")
        if conn:
            conn.rollback()
        return jsonify(
            success=False,
            error=f"Database error: {str(e)}"
        ), 500
        
    finally:
        # Clean up resources
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route("/send_message", methods=["POST"])
def send_message():
    if "admin_id" not in session:  # Ensure only admin can send messages
        flash("Admin access required.", "danger")
        return redirect(url_for("admin_dashboard"))

    message = request.form.get("message","").strip()
    section = request.form.get("section","").strip()

    if not message or not section:
        flash("Message and section are required.", "warning")
        return redirect(url_for("inbox"))
    
    conn=None
    cursor=None

    try:
        # Save the message in the database
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO web_portal.inbox (message, section) VALUES (%s, %s)",
            (message, section)
        )
        conn.commit()
        flash("Message sent successfully.", "success")
    except Exception as e:
        flash(f"Error sending message: {e}", "danger")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

    return redirect(url_for("inbox"))


@app.route("/delete_message/<int:message_id>", methods=["POST"])
def delete_message(message_id):
    if "admin_id" not in session:  # Ensure only admin can delete messages
        flash("Admin access required.", "danger")
        return redirect(url_for("admin_dashboard"))
    
    conn=None
    cursor=None

    try:
        # Delete the message from the inbox
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM web_portal.inbox WHERE id = %s", (message_id,))
        if cursor.rowcount==0:
            flash("Message not found",'warning')
            
        else:
            conn.commit()
            flash("Message deleted successfully.", "success")
    except Exception as e:
        if conn:
            conn.rollback()
        flash(f"Error deleting message: {e}", "danger")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

    return redirect(url_for("inbox"))



# ===================================================================================

@app.route("/feedback")
def feedback():
    return render_template("feedback.html")

@app.route("/about-us")
def about_us():
    return render_template("about_us.html")

# =================== Forgot Password ===================
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")

        if email and username:
            token = str(uuid.uuid4())
            session.update({
                "reset_token": token,
                "reset_email": email,
                "token_expiry": (datetime.now() + timedelta(hours=1)).isoformat()
            })
            return redirect(url_for("reset_password", token=token))
        flash("Both email and username are required.", "warning")
    return render_template("forgot_password.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    saved_token = session.get("reset_token")
    saved_email = session.get("reset_email")
    expiry = session.get("token_expiry")

    if not saved_token or token != saved_token or datetime.now() > datetime.fromisoformat(expiry):
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        if new_password != confirm_password:
            flash("Passwords do not match.", "warning")
            return redirect(url_for("reset_password", token=token))

        hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        update_password(saved_email, hashed_pw)

        session.pop("reset_token", None)
        session.pop("reset_email", None)
        session.pop("token_expiry", None)

        flash("Password reset successful.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)

# ================== For Music And Videos ============================

@app.route("/explore")
def explore():
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(cursor_class=MySQLCursorDict,dictionary=True)

        # Fetch music
        music_data = [
            {"title": "Song 1", "artist": "Artist A", "link": "https://example.com/song1"},
            {"title": "Song 2", "artist": "Artist B", "link": "https://example.com/song2"},
        ]

        # Fetch videos from DB
        cursor.execute("SELECT title, youtube_link FROM web_portal.videos ORDER BY created_at DESC")
        video_data = cursor.fetchall()

    except Exception as e:
        flash("Error fetching explore content.", "danger")
        music_data, video_data = [], []
        print(e)
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

    return render_template("explore.html", music=music_data, vid=video_data)

# ===================== Music Page ===================
@app.route("/music")
def music():
    music_data = [
        {"title": "Song 1", "artist": "Artist A", "link": "https://example.com/song1"},
        {"title": "Song 2", "artist": "Artist B", "link": "https://example.com/song2"},
    ]
    return render_template("music.html", music=music_data)
# =====================Video Page=================================

def extract_video_id(link):
    # Extracts video ID from full URL or just returns the ID if already clean
    match = re.search(r"(?:v=|\/)([0-9A-Za-z_-]{11})", link)
    return match.group(1) if match else link

@app.route("/videos")
def videos():
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, title, youtube_link FROM videos ORDER BY created_at DESC")
        video_data = cursor.fetchall()

        # Log the video data to make sure you get the correct video IDs
        print("Fetched videos:", video_data)  # Add this line

        # Construct the full YouTube URL (if needed)
        cleaned_videos=[]
        for video in video_data:
            video=dict(video)
            video['youtube_link'] = extract_video_id(video['youtube_link'])
            cleaned_videos.append(video)

        return render_template("videos.html", videos=cleaned_videos)

    except Exception as e:
        flash("Failed to load videos", "danger")
        return render_template("videos.html", videos=[])

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/admin/add_videos_item", methods=["POST"])
def add_videos_item():
    # 1. Verify session and content type
    if "admin_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
        
    if not request.is_json:
        return jsonify({"success": False, "error": "Request must be JSON"}), 400

    try:
        # 2. Parse data
        data = request.get_json()
        title = data.get("title", "").strip()
        raw_link = data.get("link", "").strip()

        # 3. Validate input
        if not title:
            return jsonify({"success": False, "error": "Title is required"}), 400
            
        # 4. Extract YouTube ID
        video_id = None
        if "youtube.com/watch?v=" in raw_link:
            video_id = raw_link.split("v=")[1].split("&")[0]
        elif "youtu.be/" in raw_link:
            video_id = raw_link.split("youtu.be/")[1].split("?")[0]
        elif len(raw_link) == 11:  # Assume raw ID
            video_id = raw_link
            
        if not video_id or len(video_id) != 11:
            return jsonify({"success": False, "error": "Invalid YouTube URL"}), 400

        # 5. Save to database
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO videos (title, youtube_link, created_at) VALUES (%s, %s, NOW())",
            (title, video_id))
        conn.commit()
        
        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

        
@app.route("/admin/get_videos")
def get_videos():
    if "admin_id" not in session:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, title, youtube_link FROM videos ORDER BY created_at DESC")
        videos = cursor.fetchall()
        return jsonify({"videos": videos})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route("/admin/delete_videos_item/<int:item_id>", methods=["DELETE"])
def delete_videos_item(item_id):
    if "admin_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM videos WHERE id = %s", (item_id,))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
        
        
# =======================E-Commerce=======================================

@app.route('/ecommerce')
def ecommerce():
    try:
        with db_cursor() as cursor:
            cursor.execute("""
                SELECT id, name, description, price, image_url, 
                       buy_now_enabled, buy_now_text 
                FROM products
                WHERE buy_now_enabled = 1
            """)
            products = cursor.fetchall()
        
        return render_template('ecommerce.html', products=products)
    
    except Exception as e:
        logger.exception("Error loading products in /ecommerce")
        flash('Error loading products. Please try again later.', 'danger')
        return render_template('ecommerce.html', products=[])
    
@app.route('/test-navbar')
def test_navbar():
    return render_template('navbar.html')



@app.route('/admin/orders')
def admin_orders():
    if "admin_id" not in session:
        flash("Admin access required", "danger")
        return redirect(url_for("admin_login"))

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('''
            SELECT o.*, p.name as product_name, u.username as customer_name
            FROM orders o
            JOIN products p ON o.product_id = p.id
            JOIN users u ON o.user_id = u.id
            ORDER BY o.created_at DESC
        ''')
        orders = cursor.fetchall()
        
        return render_template("admin_orders.html", orders=orders)
    except Exception as e:
        flash(f"Error loading orders: {str(e)}", "danger")
        return render_template("admin_orders.html", orders=[])
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/admin/update_order_status/<order_id>', methods=['POST'])
def update_order_status(order_id):
    if "admin_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 403
        
    new_status = request.json.get('status')
    if new_status not in ['pending', 'processing', 'shipped', 'delivered', 'cancelled']:
        return jsonify({"success": False, "error": "Invalid status"}), 400
        
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE orders SET status = %s 
            WHERE order_id = %s
        ''', (new_status, order_id))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/buy-now/<int:product_id>')
@login_required
def buy_now(product_id):
    # Step 1: Check session
    user_id = session.get('user_id')
    session_token = session.get('session_token')

    if not user_id or not session_token:
        session['next_url'] = url_for('buy_now', product_id=product_id)
        return redirect(url_for('login'))

    try:
        with db_cursor() as cursor:
            # Step 2: Validate active session
            cursor.execute("""
                SELECT is_logged_in 
                FROM user_sessions 
                WHERE user_id = %s 
                  AND session_token = %s 
                  AND last_activity > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            """, (user_id, session_token))
            result = cursor.fetchone()

            if not result or not result['is_logged_in']:
                session.clear()
                session['next_url'] = url_for('buy_now', product_id=product_id)
                return redirect(url_for('login'))

            # Step 3: Update last activity
            cursor.execute("""
                UPDATE user_sessions 
                SET last_activity = CURRENT_TIMESTAMP 
                WHERE user_id = %s AND session_token = %s
            """, (user_id, session_token))

            # Step 4: Fetch product
            cursor.execute("""
                SELECT * 
                FROM products 
                WHERE id = %s AND buy_now_enabled = 1
            """, (product_id,))
            product = cursor.fetchone()

            if product:
                return render_template('checkout.html', product=product)

    except Exception as e:
        logger.exception(f"Error in buy_now route for product_id {product_id}")
        flash('An error occurred while processing your request.', 'danger')

    flash('Product not available', 'danger')
    return redirect(url_for('ecommerce'))

@app.route('/fashion')
def fashion():
    return render_template('fashion.html')  # Create this file in templates/


@app.route('/process-checkout', methods=['POST'])
@login_required
def process_checkout():
    try:
        logger.debug("Checkout process started")

        product_id = request.form.get('product_id')
        quantity = int(request.form.get('quantity', 1))

        # Get address parts from form
        address = request.form.get('address', '').strip()
        city = request.form.get('city', '').strip()
        pincode = request.form.get('pincode', '').strip()

        user_id = current_user.id

        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)

        # ✅ Verify product
        cursor.execute(
            'SELECT id, name, price FROM products WHERE id = %s AND buy_now_enabled = 1',
            (product_id,)
        )
        product = cursor.fetchone()
        if not product:
            flash('Product not available', 'danger')
            return redirect(url_for('ecommerce'))

        total_price = float(product['price']) * quantity
        order_id = str(uuid.uuid4())

        # ✅ Insert order
        cursor.execute('''
            INSERT INTO orders (
                order_id, user_id, product_id, quantity, total_price, status,
                address, city, pincode
            )
            VALUES (%s, %s, %s, %s, %s, 'pending', %s, %s, %s)
        ''', (order_id, user_id, product_id, quantity, total_price, address, city, pincode))
        conn.commit()

        logger.info(f"Order placed successfully: {order_id}")

        # ✅ Get user info
        cursor.execute('SELECT username, email FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()

        # ✅ Build order data for email
        order_data = {
            'order_id': order_id,
            'product_name': product['name'],
            'quantity': quantity,
            'product_price': float(product['price']),
            'total_price': total_price,
            'address': address,
            'city': city,
            'pincode': pincode
        }

        # ✅ Send email
        send_order_confirmation_email(
            user_email=user['email'],
            user_fullname=user['username'],
            order=order_data
        )

        # ✅ Optional: flash success message
        flash('Your order has been placed successfully!', 'success')

        return redirect(url_for('order_confirmation', order_id=order_id))

    except Exception as e:
        logger.error(f"Checkout failed: {str(e)}", exc_info=True)
        flash('Checkout process failed', 'danger')
        return redirect(url_for('ecommerce'))

    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()


@app.route('/order-confirmation/<uuid:order_id>')
@login_required
def order_confirmation(order_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT o.*, p.name as product_name, p.image_url 
            FROM orders o
            JOIN products p ON o.product_id = p.id
            WHERE o.order_id = %s AND o.user_id = %s
        """, (str(order_id), current_user.id))

        order = cursor.fetchone()

        if not order:
            flash('Order not found', 'danger')
            return redirect(url_for('ecommerce'))

        return render_template('order_confirmation.html', 
                               order=order,
                               include_footer=False)
    except Exception as e:
        app.logger.error(f"Order confirmation error: {str(e)}")
        flash('Error loading order details', 'danger')
        return redirect(url_for('ecommerce'))
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

        
@app.route('/debug/last-order')
@login_required
def debug_last_order():
    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('''
        SELECT * FROM orders 
        WHERE user_id = %s 
        ORDER BY created_at DESC LIMIT 1
    ''', (current_user.id,))
    order = cursor.fetchone()
    cursor.close()
    conn.close()
    return jsonify(order or {"error": "No orders found"})

@app.route('/admin/add_products_item', methods=['POST'])
def add_product():
    if not request.is_json:
        return jsonify({'success': False, 'error': 'Request must be JSON'}), 400
        
    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    price = data.get('price')
    image_url = data.get('image_url', '').strip()
    buy_now_enabled = data.get('buy_now_enabled', 1)  # Default to enabled
    buy_now_text = data.get('buy_now_text', 'Buy Now')  # Default text

    # Validation
    if not name:
        return jsonify({'success': False, 'error': 'Product name is required'}), 400
    if not price:
        return jsonify({'success': False, 'error': 'Price is required'}), 400
    
    try:
        price = float(price)
        if price <= 0:
            return jsonify({'success': False, 'error': 'Price must be positive'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'error': 'Invalid price format'}), 400

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        # Check if columns exist
        cursor.execute('SHOW COLUMNS FROM products LIKE "buy_now_enabled"')
        has_buy_now = cursor.fetchone()
        
        if has_buy_now:
            cursor.execute('''
                INSERT INTO products 
                (name, description, price, image_url, buy_now_enabled, buy_now_text) 
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (name, description, price, image_url, buy_now_enabled, buy_now_text))
        else:
            cursor.execute('''
                INSERT INTO products 
                (name, description, price, image_url) 
                VALUES (%s, %s, %s, %s)
            ''', (name, description, price, image_url))
            
        conn.commit()
        return jsonify({
            'success': True, 
            'id': cursor.lastrowid,
            'message': 'Product added successfully'
        })
    except Exception as e:
        app.logger.error(f"Error adding product: {str(e)}")
        return jsonify({'success': False, 'error': 'Database error'}), 500
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()
        
        
@app.route('/admin/get_products')
def get_products():
    if "admin_id" not in session:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('''
            SELECT id, name, description, price, image_url, 
                   buy_now_enabled, buy_now_text 
            FROM products
        ''')
        rows = cursor.fetchall()

        # Ensure price is sent as float (not string)
        products = []
        for row in rows:
            row['price'] = float(row['price']) if row['price'] is not None else 0.0
            products.append(row)

        return jsonify({"products": products})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/admin/update_product/<int:product_id>', methods=['PUT'])
def update_product(product_id):
    if "admin_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 403
        
    data = request.get_json()
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE products SET
                name = %s,
                description = %s,
                price = %s,
                image_url = %s,
                buy_now_enabled = %s,
                buy_now_text = %s
            WHERE id = %s
        ''', (
            data.get('name'),
            data.get('description'),
            data.get('price'),
            data.get('image_url'),
            data.get('buy_now_enabled', 0),
            data.get('buy_now_text', 'Buy Now'),
            product_id
        ))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/add-to-cart', methods=['POST'])
@login_required
def add_to_cart():
    try:
        product_id = int(request.form.get('product_id'))
        quantity = int(request.form.get('quantity', 1))
        user_id = current_user.id if current_user.is_authenticated else session.get('user_id')
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401
            
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        # Check if item already in cart
        cursor.execute('''
            SELECT id, quantity FROM cart 
            WHERE user_id = %s AND product_id = %s
        ''', (user_id, product_id))
        existing = cursor.fetchone()
        
        if existing:
            # Update quantity
            new_quantity = existing[1] + quantity
            cursor.execute('''
                UPDATE cart SET quantity = %s 
                WHERE id = %s
            ''', (new_quantity, existing[0]))
        else:
            # Add new item
            cursor.execute('''
                INSERT INTO cart (user_id, product_id, quantity)
                VALUES (%s, %s, %s)
            ''', (user_id, product_id, quantity))
            
        conn.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        app.logger.error(f"Error adding to cart: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route('/remove-from-cart/<int:item_id>', methods=['POST'])
@login_required
def remove_from_cart(item_id):
    try:
        user_id = current_user.id if current_user.is_authenticated else session.get('user_id')
        if not user_id:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401
            
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM cart 
            WHERE id = %s AND user_id = %s
        ''', (item_id, user_id))
        
        conn.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        app.logger.error(f"Error removing from cart: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()
        
# =============Database-Schema=======================================
def check_database_schema():
    required_columns = {
        'products': ['id', 'name', 'description', 'price', 'image_url', 'buy_now_enabled', 'buy_now_text'],
        'orders': ['id', 'order_id', 'user_id', 'product_id', 'quantity', 'total_price', 'status', 'created_at']
    }
    
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        for table, columns in required_columns.items():
            cursor.execute(f"SHOW COLUMNS FROM {table}")
            existing_columns = [col[0] for col in cursor.fetchall()]
            
            for col in columns:
                if col not in existing_columns:
                    logger.error(f"Missing column {col} in table {table}")
                    return False
                    
        return True
    except Exception as e:
        logger.error(f"Schema validation failed: {e}")
        return False
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Call this at startup
if not check_database_schema():
    logger.error("Database schema validation failed!")
    
# =========================debug==============================================
@app.route('/debug/template')
def debug_template():
    def check_login_status(user_id):
        conn = None
        cursor = None
        try:
            conn = get_mysql_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT is_logged_in 
                FROM user_sessions 
                WHERE user_id = %s
                AND last_activity > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            """, (user_id,))
            result = cursor.fetchone()
            return bool(result[0]) if result else False
        except Exception as e:
            logger.error(f"Error checking login status: {e}")
            return False
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
    
    test_user_id = 1  # Use a valid user ID from your database
    status = check_login_status(test_user_id)
    
    return render_template_string("""
        <h2>Debug Information</h2>
        <p>User ID: {{ user_id }}</p>
        <p>Status: {% if status %}Logged In{% else %}Logged Out{% endif %}</p>
    """, user_id=test_user_id, status=status)
    

# ========================for invoice-pdf-download=============================

@app.route('/order/invoice/download/<string:order_id>')
@login_required
def download_invoice(order_id):
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT o.*, p.name AS product_name, p.price AS product_price,
                   u.username, u.email, u.mobilenumber, o.created_at
            FROM orders o
            JOIN products p ON o.product_id = p.id
            JOIN users u ON o.user_id = u.id
            WHERE o.order_id = %s AND o.user_id = %s
        """, (order_id, current_user.id))

        order = cursor.fetchone()
        if not order:
            abort(404, description="Order not found.")

        # Convert created_at to datetime
        if isinstance(order['created_at'], str):
            order_date = datetime.strptime(order['created_at'], '%Y-%m-%d %H:%M:%S')
        else:
            order_date = order['created_at']

        # Load logo image as base64
        logo_base64 = None
        logo_path = os.path.join(app.root_path, 'static', 'images', 'live_logo.png')
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as f:
                logo_base64 = base64.b64encode(f.read()).decode("utf-8")

        # Prepare simplified invoice data
        invoice_data = {
            'order_id': order['order_id'],
            'product_name': order['product_name'],
            'quantity': order['quantity'],
            'product_price': float(order['product_price']),
            'total_price': float(order['total_price']),
            'customer_name': order['username'],
            'customer_email': order['email'],
            'customer_mobile': order['mobilenumber'],
            'address': order.get('address', ''),
            'city': order.get('city', ''),
            'pincode': order.get('pincode', ''),
            'date': order_date.strftime('%d-%m-%Y'),
        }

        # Render PDF
        pdf = generate_invoice_pdf(invoice_data, logo_base64)

        return send_file(
            pdf,
            as_attachment=True,
            download_name=f"Invoice_{order_id}.pdf",
            mimetype='application/pdf'
        )

    except Exception as e:
        app.logger.error(f"[Invoice Download Error] {str(e)}")
        abort(500, description="Internal Server Error")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def generate_invoice_pdf(order, logo_base64):
    rendered_html = render_template(
        'invoice_template.html',
        order=order,
        logo_base64=logo_base64,
        current_time=datetime.now().strftime('%d-%m-%Y %H:%M')
    )

    pdf_io = BytesIO()
    HTML(string=rendered_html).write_pdf(pdf_io)
    pdf_io.seek(0)
    return pdf_io

# ==================view-orders==============================================

class OrderItem:
    def __init__(self, product_id, product_name, quantity, unit_price, total_price, image_url):
        self.product_id = product_id
        self.product_name = product_name
        self.quantity = quantity
        self.unit_price = unit_price
        self.total_price = total_price
        self.image_url = image_url

class Order:
    def __init__(self, order_id, status, created_at, shipping_address, items, order_total):
        self.order_id = order_id
        self.status = status
        self.created_at = created_at
        self.shipping_address = shipping_address
        self.items = items  # list of OrderItem
        self.order_total = order_total
        
@app.route('/view-orders')
@login_required
def view_user_orders():
    try:
        user_id = current_user.id

        # Fetch orders as list of dicts grouped by order_id
        orders_data = get_orders_grouped_by_order_id(user_id)

        orders = []
        for o in orders_data:
            # Parse created_at safely
            created_at = o['created_at']
            if isinstance(created_at, str):
                for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S'):
                    try:
                        created_at = datetime.strptime(created_at, fmt)
                        break
                    except ValueError:
                        continue

            # Build list of OrderItem objects
            items = [
                OrderItem(
                    product_id=i['product_id'],
                    product_name=i['product_name'],
                    quantity=i['quantity'],
                    unit_price=i['unit_price'],
                    total_price=i['total_price'],
                    image_url=i['image_url']
                ) for i in o['items']
            ]

            # Create Order object
            order = Order(
                order_id=o['order_id'],
                status=o['status'],
                created_at=created_at,
                shipping_address=o['shipping_address'],
                items=items,
                order_total=o['order_total']
            )
            orders.append(order)

        return render_template(
            "view_orders.html",
            orders=orders,
            current_user=current_user,
            timedelta=timedelta  # in case you're showing "time since placed"
        )

    except Exception as e:
        app.logger.error(f"[view_user_orders] Error: {str(e)}")
        flash("An error occurred while loading your orders.", "danger")
        return redirect(url_for("ecommerce"))
    
def get_user_info(user_id):
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT name, email, mobilenumber FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        return user or {}

    except Exception as e:
        app.logger.error(f"[ERROR] get_user_info: {e}")
        return {}



def get_orders_grouped_by_order_id(user_id):
    try:
        with get_mysql_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                query = """
                    SELECT o.order_id, o.status, o.created_at,
                           o.address, o.city, o.pincode,
                           o.product_id, o.quantity, o.total_price,
                           p.name as product_name, p.price as product_price, p.image_url
                    FROM orders o
                    JOIN products p ON o.product_id = p.id
                    WHERE o.user_id = %s
                    ORDER BY o.created_at DESC
                """
                cursor.execute(query, (user_id,))
                rows = cursor.fetchall()

                orders = {}
                for row in rows:
                    order_id = row['order_id']

                    # ✅ Build shipping address from parts
                    address_parts = [row.get('address', ''), row.get('city', ''), row.get('pincode', '')]
                    shipping_address = ', '.join(part for part in address_parts if part)

                    if order_id not in orders:
                        orders[order_id] = {
                            'order_id': order_id,
                            'status': row['status'],
                            'created_at': row['created_at'],
                            'shipping_address': shipping_address or "No shipping address provided",
                            'items': [],
                            'order_total': 0
                        }

                    orders[order_id]['items'].append({
                        'product_id': row['product_id'],
                        'product_name': row['product_name'],
                        'quantity': row['quantity'],
                        'unit_price': row['product_price'],
                        'total_price': row['total_price'],
                        'image_url': row['image_url']
                    })
                    orders[order_id]['order_total'] += float(row['total_price'])

                return list(orders.values())

    except Exception as e:
        app.logger.error(f"Database error in get_orders_grouped_by_order_id: {str(e)}")
        return []


# ===============Some Bonus Tips======================================================

@app.route('/admin/get_music')
def get_music():
    # return music data as JSON
    return jsonify([])

@app.route('/admin/get_dashboard_metrics')
def get_dashboard_metrics():
    # return some metrics
    return jsonify({})

@app.route('/admin/get_recent_uploads')
def get_recent_uploads():
    # return recent uploads
    return jsonify([])


# ======================chatbot-route==============================================

import json

with open("data/faq.json", "r") as f:
    faq_data = json.load(f)
    
@app.route("/get", methods=["POST"])
def chatbot_response():
    user_msg = request.json.get("message", "").lower()
    response = "Sorry, I didn't understand that."

    best_match = None
    highest_score = 0

    for question, answer in faq_data.items():
        score = 0
        for word in user_msg.split():
            if word in question.lower():
                score += 1

        if score > highest_score:
            highest_score = score
            best_match = answer

    if highest_score > 0:
        response = best_match

    return jsonify({"response": response})
# =================== Run App ===================
if __name__ == "__main__":
    app.run(port=5001, debug=True)
