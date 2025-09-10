# conn_db.py
import os
import re
import bcrypt
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv

# WE USE THE Environment variables FOR SAFE THE API, PASSWORD etc...
# FOR SECURITY PURPOSE THE .env FILE VARIBLE WANT TO STORE IN SECURE SERVER TO USE 
# NOT UPLOAD IN GITHUB I AM USING LEARNING PURPOSE

load_dotenv()  # optional .env support



class Database:
    def __init__(self):
        try:
            # MYSQL CONNECTOR IS USED FOR TO CONNECT TO THE DB
            self.conn = mysql.connector.connect(
                # REPLACE YOUR DB SERVER
                host=os.getenv("Replace Your hostname"), 
                user=os.getenv("Replace Your User name"), 
                password=os.getenv("Replace Your Password"), 
                database=os.getenv("Replace Your Database")
            )

            # TO INTIMATE THE CONNECTION IS SUCCESFULL
            if self.conn.is_connected():
                print("✅ Connected to database")
        except Error as e:
            print("❌ Database connection failed:", e)
            self.conn = None


    # IF THE USER LEFT CLOSE THE CONNECTION
    def close(self):
        if self.conn and self.conn.is_connected():
            self.conn.close()
            print("🔒 DB connection closed")


    # TO CHECK THE ANY MALICOUS SQL INJECTION HAPPEN
    # THIS IS FOR PREVENT FROM THE SQL INJECTION
    # REGAX IS USED FOR AVOID SQL IJECTION
    def is_safe_username(self, username: str) -> bool:
        # allow letters, numbers, ., @, -, _
        return bool(re.match(r'^[A-Za-z0-9_.@-]{3,150}$', username))

    # THIS FUNCTION FOR REGISTRATION  
    # TO INSERT THE NEW USER DATA INTO THE DATABASE
    def create_user(self, username: str, plain_password: str) -> tuple[bool, str]:
        """Return (success, message)"""
        if not self.conn:
            return False, "No DB connection"
        if not self.is_safe_username(username):
            return False, "Invalid username (only letters/numbers/._@- allowed, 3-150 chars)"

        try:
            # CUSOR FOR TO USE THE SQL QUERY IN PYTHON
            cursor = self.conn.cursor()

            # BCRYPT IS USED FOR TO ENCRYPT THE PASSWORD TO STORE FOR SECURITY PURPOSE
            hashed = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()

            # SQL QUERY TO INSERT
            sql = "INSERT INTO chat_app (username, password) VALUES (%s, %s)"
            cursor.execute(sql, (username, hashed))
            self.conn.commit()
            cursor.close()

            return True, "User registered"
        
        
        except mysql.connector.IntegrityError:
            return False, "Username already exists"
        except Exception as e:
            return False, f"DB error: {e}"

    # THIS FUNCTION FOR LOGIN
    # TO VERIFY THE USER LOGIN DATA IS VALID OR NOT
    # TO ALLOW THE USER 

    def verify_user(self, username: str, plain_password: str) -> tuple[bool, str]:
        """Return (ok, msg). On success msg = stored_hash (string) or some info."""
        if not self.conn:
            return False, "No DB connection"


        try:
            cursor = self.conn.cursor()
            sql = "SELECT password FROM chat_app WHERE username=%s"
            cursor.execute(sql, (username,))
            row = cursor.fetchone()
            cursor.close()
            if not row:
                return False, "User not found"

            stored_hash = row[0]
            # bcrypt check: stored_hash is str, convert to bytes
            if bcrypt.checkpw(plain_password.encode(), stored_hash.encode()):
                return True, "Verified"
            else:
                return False, "Invalid credentials"
        except Exception as e:
            return False, f"DB error: {e}"
