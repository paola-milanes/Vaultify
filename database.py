import sqlite3
from cryptography.fernet import Fernet
import os

def load_key():
    key_path = os.path.join(os.path.dirname(__file__), 'key.key')
    print(f"Looking for key at: {key_path}")
    if not os.path.exists(key_path):
        print(f"Key file does not exist at {key_path}. Generating a new key...")
        key = Fernet.generate_key()
        with open(key_path, 'wb') as key_file:
            key_file.write(key)
        print(f"New key saved to {key_path}")
    else:
        print(f"Key file found at {key_path}. Loading the key...")
        try:
            with open(key_path, 'rb') as key_file:
                key = key_file.read()
            print(f"Key successfully loaded from {key_path}")
        except Exception as e:
            print(f"Error reading key file: {e}")
            exit(1)
    return key

key = load_key()
cipher = Fernet(key)

def drop_users_table():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users')
    conn.commit()
    conn.close()

def create_users_table():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            otp_secret TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def drop_passwords_table():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS passwords')
    conn.commit()
    conn.close()

def create_passwords_table():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def add_password(site, username, password):
    encrypted_password = cipher.encrypt(password.encode())
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (site, username, password) VALUES (?, ?, ?)", (site, username, encrypted_password))
    conn.commit()
    conn.close()

def get_passwords(encrypted=False):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords")
    data = cursor.fetchall()
    conn.close()

    decrypted_data = []
    for row in data:
        try:
            if encrypted:
                decrypted_password = cipher.decrypt(row[3]).decode()
                decrypted_data.append((row[0], row[1], row[2], decrypted_password))
            else:
                decrypted_data.append((row[0], row[1], row[2], row[3]))
        except Exception as e:
            print(f"Error decrypting password for site {row[1]}: {e}")
    return decrypted_data

def search_passwords(query, encrypted=False):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords WHERE site LIKE ?", ('%' + query + '%',))
    data = cursor.fetchall()
    conn.close()
    if encrypted:
        return [(row[0], row[1], row[2], row[3]) for row in data]
    else:
        decrypted_data = []
        for row in data:
            try:
                decrypted_password = cipher.decrypt(row[3]).decode()
                decrypted_data.append((row[0], row[1], row[2], decrypted_password))
            except Exception as e:
                print(f"Error decrypting password for site {row[1]}: {e}")
        return decrypted_data

def delete_password(id):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE id = ?", (id,))
    conn.commit()
    conn.close()

def decrypt_all_passwords():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords")
    data = cursor.fetchall()
    conn.close()

    decrypted_data = []
    for row in data:
        try:
            decrypted_password = cipher.decrypt(row[3]).decode()
            decrypted_data.append((row[0], row[1], row[2], decrypted_password))
        except Exception as e:
            print(f"Error decrypting password for site {row[1]}: {e}")

    return decrypted_data

def update_password_in_db(id, new_password):
    try:
        encrypted_password = cipher.encrypt(new_password.encode())
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE passwords SET password = ? WHERE id = ?", (encrypted_password, id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error updating password: {e}")
        return False

# Test encryption and decryption
test_string = "TestPassword"
print(f"Original string: {test_string}")

# Encrypt the string
encrypted = cipher.encrypt(test_string.encode())
print(f"Encrypted string: {encrypted}")

# Decrypt the string
decrypted = cipher.decrypt(encrypted).decode()
print(f"Decrypted string: {decrypted}")

# Verify that the decrypted string matches the original
assert test_string == decrypted, "Decrypted text doesn't match the original!"

# Add a test password
# add_password("example.com", "testuser", "TestPassword123")

# Retrieve and print encrypted passwords
passwords = get_passwords(encrypted=True)
for password in passwords:
    print(f"Site: {password[1]}, Username: {password[2]}, Decrypted Password: {password[3]}")

# Update password for a specific entry
# password_id = 1  # Use the appropriate ID for the entry you want to update
# new_password = "NewTestPassword123"

# success = update_password_in_db(password_id, new_password)
# if success:
#     print("Password updated successfully.")
#     # Verify by retrieving and decrypting
#     updated_passwords = get_passwords(encrypted=True)
#     for password in updated_passwords:
#         if password[0] == password_id:
#             print(f"Updated Password for ID {password_id}: {password[3]}")
# else:
#     print("Error updating password.")
