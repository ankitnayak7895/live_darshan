from db.mysqldb import authenticate_admin

admin = authenticate_admin("adminankit", "admin1234")
print(admin)
