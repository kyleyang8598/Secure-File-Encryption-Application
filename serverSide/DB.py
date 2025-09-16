import ServerSide
import HashDB
import threading
import queue
import time
import sqlite3
import hmac
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import os
import email_send


class DataBase:
    def __init__(self):
        """Initialize database and start server in a separate thread."""
        self.data_queue = queue.Queue()  # Queue for storing received data
        self.server = ServerSide.SecureTCPServer(data_queue=self.data_queue)
        self.hashDB = HashDB.Hash()

        # Start the server in a thread
        self.server_thread = threading.Thread(target=self.server.start_server, daemon=True)
        self.server_thread.start()

        # Start a thread to process incoming data
        self.processing_thread = threading.Thread(target=self.process_data, daemon=True)
        self.processing_thread.start()

        # Creating database
        self.DB_name = 'DB.db'
        self.conn = sqlite3.connect(self.DB_name)  # Creates a local DB file
        self.cursor = self.conn.cursor()

        # Create the users table if it doesn't exist
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            email_salt TEXT NOT NULL,
            password TEXT NOT NULL,
            password_salt TEXT NOT NULL
        )
        ''')
        self.conn.commit()
        self.conn.close()
        
        # Config Header
        self.userIDPos = 0
        self.emailPos = 1
        self.emailSaltPos = 2
        self.passwordPos = 3
        self.passwordSaltPos = 4

    def process_data(self):
        """Continuously processes data received from the server."""
        while True:
            data = self.data_queue.get() # Get data from the queue
            
            if data is None:
                break
            
            elif type(data) == str:
                print(f'Processing Data: {data}')
                print(f'DATA: {data}')
                data_split = data.split(':')

                if ("create-email" and "create-password") in data_split: # Format [create-email:email:create-password:password]
                    print('NEW USER')
                    email = data_split[1].lower()
                    password = data_split[-1]
                    self.store(email=email, password=password)
                    
                elif ("email" and "password") in data_split: # Format [email:data:password:data:AESKEY]
                    print("EXISTING USER")
                    email = data_split[1].lower()
                    password = data_split[-2]
                    AESkey = base64.b64decode(data_split[-1])
                    self.checkDB(email=email, password=password, retrieve=True, key=AESkey)
                
                elif ("recover-email" and "recover-password") in data_split: # Format [recover-email:email:recover-password:password:AESKEY]
                    email = data_split[1].lower()
                    password = data_split[-2]
                    AESkey = base64.b64decode(data_split[-1])
                    check = self.check_temp_password(email, password)
                    if check:
                        os.remove(email)
                        checkingDB = self.checkDB(email, password, key=AESkey, internal=False, retrieve=True, recovery=True)
                        if type(checkingDB) is tuple:
                            _, old_password = checkingDB
                            self.remove_replace(current_data=(email,old_password), new_data=(email,password), dataType='recovery')
                    
                    else:
                        self.server.handle_client('404'.encode())
                        
                elif "recover-email" in data_split:
                    email = data_split[-1].lower()
                    check_exists = self.checkDB(email=email, password=None, internal=True)
                    if check_exists:
                        temp_password = self.generate_temp_password()
                        with open(email, 'w') as tempfile:
                            tempfile.write(temp_password)
                        print("SENDING EMAIL")
                        email_sending = email_send.tempPassword(email=email, temp_password=temp_password)
                        email_sending.sendEmail()

                elif 'delete' in data_split: # Format [delete:email:password]
                    email = data_split[1].lower()
                    password = data_split[-1]

                    self.remove_replace(current_data=(email, password), new_data=None, dataType='delete')
                
                elif 'change' in data_split: # Format [change:email:password:new_password]
                    email = data_split[1].lower()
                    password = data_split[2]
                    new_password = data_split[-1]

                    self.remove_replace(current_data=(email, password), new_data=(email, new_password), dataType='password')

                else:
                    print("Other Data:", data)
                    
    def store(self, email:str, password:str):
        """Stores new user data in database"""
        # Checks if user is in DB first before creating new account
        if self.checkDB(email=email, password=password, internal=True):
            print("User Already Exists.")
            return
        else:
            pass

        # Hashing Email and Password
        email_hashed, email_salt = self.hashDB.deriveHashDB(email)
        password_hashed, password_salt = self.hashDB.deriveHashDB(password)

        # Writing to DB
        conn = sqlite3.connect(self.DB_name)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (email, email_salt, password, password_salt)
            VALUES (?, ?, ?, ?)
                            ''', (email_hashed, email_salt, password_hashed, password_salt))
        conn.commit()
        conn.close()

    def remove_replace(self, current_data:tuple, new_data:tuple|None, dataType = None): # Format (email, password)
        conn = sqlite3.connect(self.DB_name)
        cursor = conn.cursor()

        # Step 1: Get all email hashes and salts
        cursor.execute('SELECT id FROM users')
        userIDs = cursor.fetchall()

        for userID in userIDs:
            cursor.execute('SELECT * FROM users WHERE id = ?', userID)
            user = cursor.fetchone()
            
            userID = userID[0]

            # # Replace Email
            # if dataType == 'email':
            #     email_salt = user[self.emailSaltPos]
            #     email_hashed = user[self.emailPos]
            #     email_hashed_check, _ = self.hashDB.deriveHashDB(current_data, email_salt)

            #     if hmac.compare_digest(email_hashed, email_hashed_check):
            #         # Derive new hash and new salt for new email
            #         new_hash, new_salt = self.hashDB.deriveHashDB(new_data)
            #         cursor.execute('''
            #         UPDATE users
            #         SET password = ?, password_salt = ?
            #         WHERE id = ?
            #     ''', (new_hash, new_salt, userID))
                    
            #         conn.commit()
            #         print(f"User ID {userID} password updated.")
            #         break
            
            # Replace Password
            if dataType == 'password':
                email_salt = user[self.emailSaltPos]
                password_salt = user[self.passwordSaltPos]
                email_hashed = user[self.emailPos]
                password_hashed = user[self.passwordPos]

                (email, password) = current_data
                (_, new_password) = new_data

                email_check, _ = self.hashDB.deriveHashDB(email, email_salt)
                password_check, _ = self.hashDB.deriveHashDB(password, password_salt)

                if hmac.compare_digest(email_hashed, email_check) and hmac.compare_digest(password_hashed, password_check):
                    # Derive new hash and new salt for new password
                    new_hash, new_salt = self.hashDB.deriveHashDB(new_password)

                    cursor.execute('''
                    UPDATE users
                    SET password = ?, password_salt = ?
                    WHERE id = ?
                ''', (new_hash, new_salt, userID))
                    
                    conn.commit()
                    print(f"User ID {userID} password updated.")
                    break
            
            # Account Deletion
            if dataType == 'delete':
                email_salt = user[self.emailSaltPos]
                password_salt = user[self.passwordSaltPos]
                email_hashed = user[self.emailPos]
                password_hashed = user[self.passwordPos]

                (email, password) = current_data

                email_check, _ = self.hashDB.deriveHashDB(email, email_salt)
                password_check, _ = self.hashDB.deriveHashDB(password, password_salt)

                if hmac.compare_digest(email_hashed, email_check) and hmac.compare_digest(password_hashed, password_check):
                    cursor.execute('DELETE FROM users WHERE id = ?', (userID,))
                    conn.commit()
                    print(f"User ID {userID} account deleted.")
                    break

            if dataType == 'recovery':
                email_hashed = user[self.emailPos]
                email_salt = user[self.emailSaltPos]
                password_hashed = user[self.passwordPos]
                password_salt = user[self.passwordSaltPos]

                (email, password) = current_data
                (_, new_password) = new_data

                email_check, _ = self.hashDB.deriveHashDB(email, email_salt)
                password_check, _ = self.hashDB.deriveHashDB(password, password_salt)

                if hmac.compare_digest(email_hashed, email_check):
                    new_hash, new_salt = self.hashDB.deriveHashDB(new_password)
                    cursor.execute('''
                    UPDATE users
                    SET password = ?, password_salt = ?
                    WHERE id = ?
                ''', (new_hash, new_salt, userID))
                    
                    conn.commit()
                    print(f"User ID {userID} password updated.")
                    break

        conn.close()
            

    def checkDB(self, email:str, password:str, key=None, internal=False, retrieve=False, recovery=False): #Internal means just checking email only
        """Checks user data in database to authenticate client"""
        conn = sqlite3.connect(self.DB_name)
        cursor = conn.cursor()

        # Step 1: Get all email hashes and salts
        cursor.execute('SELECT id FROM users')
        userIDs = cursor.fetchall()
        conn.close()

        for userID in userIDs:
            # Assuming schema: id, email_hashed, email_salt, password_hashed, password_salt
            conn = sqlite3.connect(self.DB_name)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', userID)
            user = cursor.fetchone()
            conn.close()

            email_salt = user[self.emailSaltPos]
            email_hashed = user[self.emailPos]
            password_salt = user[self.passwordSaltPos]
            password_hashed = user[self.passwordPos]

            # Step 2: Hash input email with this user’s email_salt
            email_hashed_check, _ = self.hashDB.deriveHashDB(email, email_salt)

            # Match found for email
            if hmac.compare_digest(email_hashed, email_hashed_check):
                if internal:
                    return True  # Only checking email
                
                if recovery: # Checking email and sending password):
                    password_encrypted_temp = base64.b64encode(self.encrypt(password_hashed, key)).decode()
                    self.server.handle_client(f'200:{password_encrypted_temp}'.encode()) # 200 user found
                    return True, password_hashed
                    
                # Final check
                password_hashed_check, _ = self.hashDB.deriveHashDB(password, password_salt)
                if hmac.compare_digest(password_hashed, password_hashed_check):
                    password_encrypted = base64.b64encode(self.encrypt(password_hashed, key)).decode()
                    self.server.handle_client(f'200:{password_encrypted}'.encode()) # 200 user found
                    return True
            
        if not internal:        
            self.server.handle_client("404".encode()) # 404 user not found
        return False  # No matching account

    def encrypt(self, content:bytes, key:bytes) -> bytes:
        """Encrypts content using AES."""
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(content, AES.block_size))
        return cipher.iv + ciphertext

    def generate_temp_password(self, length=16):
        """Generate a clean temporary password (no confusing characters)."""
        # Exclude similar-looking characters
        characters = (
            "ABCDEFGHJKLMNPQRSTUVWXYZ"  # no I or O
            "abcdefghijkmnopqrstuvwxyz"  # no l
            "23456789"  # no 0 or 1
            "!@#$%^&*()-_=+"
        )
        password = ''.join(random.choices(characters, k=length))
        return password
    
    def check_temp_password(self, email, password):
        try:
            with open(email, 'r') as tempfile:
                temp_password = tempfile.read()
                if hmac.compare_digest(temp_password, password):
                    return True
                else:
                    return False
        
        except FileNotFoundError:
            return False

    def stop(self):
        """Stops the server and processing thread properly."""
        self.data_queue.put(None)  # Send stop signal to process_data()
        self.server.stop_server()  # Stop the server
        self.server_thread.join()
        self.processing_thread.join()
        print("Database system stopped.")

if __name__ == "__main__":
    db = DataBase()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        db.stop()