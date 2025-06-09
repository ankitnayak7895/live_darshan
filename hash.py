import bcrypt

# 👇 Replace this with your chosen password
plain_password ="admin123"

# Generate the hashed version
hashed_password = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt())

# Output it
print(hashed_password.decode())


from werkzeug.security import generate_password_hash

hashed_password = generate_password_hash('Ankit@12')
print(hashed_password)

from werkzeug.security import generate_password_hash

# hashed_password = generate_password_hash('Ankit@12', method='pbkdf2:sha256', salt_length=8)
# print(hashed_password)

hashed_password = generate_password_hash('Ankit@12', method='bcrypt')
print(hashed_password)

import bcrypt


password = b"Ankit@12"  # password must be bytes
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print(hashed.decode())  # store this string in DB


import bcrypt

# Password from user input, bytes
password = b"Ankit@12"

# Password hash retrieved from DB, stored as string; encode it to bytes
stored_hash = b"$2b$12$begmpqLwJkwU6l219EspN.vxj6GMRWIHWdAB0scAaspNsJGKcugli"

# Check if password matches the stored hash
if bcrypt.checkpw(password, stored_hash):
    print("Password matches!")
else:
    print("Password incorrect!")
