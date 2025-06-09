import mysql.connector
import bcrypt

# Connect to DB
conn = mysql.connector.connect(
    host='localhost',
    user='root',
    password='Omm@12',
    database='web_portal'
)
cursor = conn.cursor()

# Admin credentials
username = 'adminankit'
email = 'ankitnayak7895@gmail.com'
raw_password = 'Adminankit@7895'
hashed_password = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Insert admin
query = "INSERT INTO web_portal.admins (username, email, password) VALUES (%s, %s, %s)"
cursor.execute(query, (username, email, hashed_password))
conn.commit()
cursor.close()
conn.close()

print("✅ Admin inserted.")
