import mysql.connector
from mysql.connector import Error
import bcrypt

def get_db_connection():
    """Establish a connection to the MySQL database."""
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='Omm@12',
            database='web_portal'
        )
        print('connection siccessful')
        return connection if connection.is_connected() else None
    except Error as e:
        print(f"[DB ERROR] MySQL Connection failed: {e}")
        return None

def register_user(username, firstname, lastname, email, mobile, password):
    """Register a new user with a securely hashed password."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(buffered=True)
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            query = """
                INSERT INTO users (username, firstname, lastname, email, mobile, password)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (username, firstname, lastname, email, mobile, hashed_password))
            connection.commit()
            print("[INFO] User registered successfully.")
    except Error as e:
        print(f"[DB ERROR] User registration failed: {e}")
        if connection:
            connection.rollback()
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def authenticate_user(username_or_email, password):
    """Authenticate a user by username or email with hashed password verification."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(buffered=True)
            query = "SELECT * FROM users WHERE username = %s OR email = %s"
            cursor.execute(query, (username_or_email, username_or_email))
            user = cursor.fetchone()
            if user:
                stored_hash = user[6]  # Password assumed at index 6
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                    return user
            return None
    except Error as e:
        print(f"[DB ERROR] User authentication failed: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

# ---------------------------- ADMIN SUPPORT ----------------------------

def register_admin(username, email, password):
    """Register a new admin (used for backend script or manual setup)."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(buffered=True)
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            query = "INSERT INTO admins (username, email, password) VALUES (%s, %s, %s)"
            cursor.execute(query, (username, email, hashed_password))
            connection.commit()
            print("[INFO] Admin registered successfully.")
    except Error as e:
        print(f"[DB ERROR] Admin registration failed: {e}")
        if connection:
            connection.rollback()
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def authenticate_admin(username, password):
    """Authenticate an admin by username and password."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(buffered=True)
            query = "SELECT * FROM admins WHERE username = %s"
            cursor.execute(query, (username,))
            admin = cursor.fetchone()
            print("[DEBUG] DB Admin record:", admin)

            if admin:
                print("[DEBUG] Admin from DB:", admin)
                if password == admin[3]:  # Plain-text match
                    print('[DEBUG] Password match:True')
                    return admin
                else:
                    print('[DEBUG] Password match:False')
            return None
    except Error as e:
        print(f"[DB ERROR] Admin authentication failed: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# ---------------------------- UPDATE PASSWORD ----------------------------

def update_password(email, new_password):
    """Update the user's password in the database."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(buffered=True)

            # Hash the new password before updating
            hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Update the user's password
            query = "UPDATE users SET password = %s WHERE email = %s"
            cursor.execute(query, (hashed_new_password, email))
            connection.commit()

            print(f"[INFO] Password for {email} updated successfully.")
            return True
    except Error as e:
        print(f"[DB ERROR] Failed to update password: {e}")
        if connection:
            connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def get_user_by_id(user_id):
    """Fetch a user by ID (required for Flask-Login session management)."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(buffered=True)
            query = "SELECT * FROM users WHERE id = %s"
            cursor.execute(query, (user_id,))
            return cursor.fetchone()
    except Error as e:
        print(f"[DB ERROR] get_user_by_id failed: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()
