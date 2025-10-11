import os
import string
import secrets
import time
import base64
import getpass # https://www.geeksforgeeks.org/python/getpass-and-getuser-in-python-password-without-echo/
import platform
import pyperclip
import sqlite3 # https://www.geeksforgeeks.org/python/python-sqlite-cursor-object/
from tabulate import tabulate
import argon2
import argon2.exceptions
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# General understanding of the difference between hashing and encryption https://pagorun.medium.com/password-encryption-in-python-securing-your-data-9e0045e039e1

### Global variables
welcome_msg = "Welcome to the My$PM\n"
guide = """To create an entry, you need to fill in:\n\n1. Entity Name - should be short and unique name which can be used to select between two accounts on the same site.\n2. Site - can be the short domain name of the site to which the account is related to, for example, \"facebook.com\".\n3. Username - can be whatever you use for login, it can be email address, your username, or actual name.\n4. Password length - how long the password you want to have.\n\nFor security purposes, I believe it would be better that you would not be able to use your own password,\ninstead the password should be generated.\nIn My$PM you can generate passwords with length 10-22 characters.\n\nIF POSSIBLE TRY TO GENERATE AS LONG OF A PASSWORD AS POSSIBLE!!!"""
find_opt = {
    "1": "Show entry",
    "2": "Search again",
    ".": "To leave press"
}
find_action = {
    "1": "Copy password",
    "2": "Delete login",
    "3": "Edit Login",
    ".": "To leave press"
}
edit_msg = """Please enter only the parts which you wish to change.\nIf you do not want to change somefield, just leave it empty"""
opt = {
    "1": "Create new Login",
    "2": "Find Login",
    ".": "To leave press"
}

# For Argon2ID
time_cost = 2          # Number of iterations
memory_cost = 102400   # 100 MB in KiB
parallelism = 8        # Number of parallel threads
hash_len = 32          # Length of the hash in bytes
salt_len = 16          # Length of the salt in bytes

# class
class DB:
    def __init__(self):
        self.db = 'Vault.db'
        with sqlite3.connect(self.db) as conn:
            c = conn.cursor()

            # Secure users table
            c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,         -- store hashed password, never plaintext
                    salt BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            c.execute('''
                CREATE TABLE IF NOT EXISTS logins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    entity_name TEXT UNIQUE NOT NULL,
                    site_name TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password_encr BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            ''')

            conn.commit()

    def run_query(self, query, params=()):
        with sqlite3.connect(self.db) as conn:
            c = conn.cursor()
            c.execute(query, params)
            return c.fetchall()

    def run_change(self, query, params=()):
        with sqlite3.connect(self.db) as conn:
            c = conn.cursor()
            c.execute(query, params)
            conn.commit()

#    def reset_seq(self):
#        with sqlite3.connect(self.db) as conn:
#            c = conn.cursor()
#            c.execute('''SELECT name FROM sqlite_master WHERE type=\'table\' AND name=\'sqlite_sequence\'''')
#            if c.fetchone():
#                c.execute('''DELETE FROM sqlite_sequence WHERE name = ?''', ("logins",))
#            conn.commit()

db = DB()

# code snipplet taken from https://hackernoon.com/argon2-in-practice-how-to-implement-secure-password-hashing-in-your-application
# Create the hasher
ph = argon2.PasswordHasher(
    time_cost=time_cost,
    memory_cost=memory_cost,
    parallelism=parallelism,
    hash_len=hash_len,
    salt_len=salt_len,
    type=argon2.Type.ID  # Using Argon2id variant
)

def hash_password(password):
    # Hash the password (salt is generated automatically)
    hash = ph.hash(password)
    return hash

#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
def clear():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")


def check_master_user():
    check = db.run_query('''SELECT COUNT(username) FROM users''')
    if check[0][0] == 0:
        return False
    else:
        return True


def create_master_user():
    username = input("Please enter your username: ")
    password = input("Please enter your password: ")
    password_hash = hash_password(password)
    salt = os.urandom(16)
    db.run_change('''INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?) ''', params=(username, password_hash, salt))


def derive_key(username, password):
    # KDF docs https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
    salt = db.run_query('''SELECT salt FROM users WHERE username = ?''', params=(username,))[0][0]
    kdf = Argon2id(
        salt=salt,
        length=hash_len,
        iterations=time_cost,
        lanes=parallelism,
        memory_cost=memory_cost,
        ad=None,
        secret=None,
    )

    key = kdf.derive(password.encode())
    return key


def password_gen(length):
    # The following code snipplet was taken from: https://www.geeksforgeeks.org/python/secrets-python-module-generate-secure-random-numbers/
    # and refined by ChatGPT
    letters = string.ascii_letters
    digits = string.digits
    specials = "!@#$%^&*-_=+,.<>?"  # only safe punctuation characters
    alphabet = letters + digits + specials

    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))  # adjust length
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and sum(c.isdigit() for c in password) >= 3
            and sum(c in specials for c in password) >= 3
        ):
            return password
            break


def create_login(user_id, key):
    while True:
        clear()
        try:
            print(f"{guide}\n")
            entity_name = input("Please give a short and unique name for the entry: ")
            site = input("Please enter the site: ")
            username = input("Please enter the username: ")
            length = input("Please enter password length(10-26): ")
            if length == "":
                length = 10
            password = password_gen(int(length))
            # Fernet algorythm code snipplet reference: https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
            # https://stackoverflow.com/questions/27335726/how-do-i-encrypt-and-decrypt-a-string-in-python
            f = Fernet(base64.urlsafe_b64encode(key))
            password_encr = f.encrypt(password.encode())
            db.run_change('''INSERT INTO logins (user_id, entity_name, site_name, username, password_encr) VALUES (?, ?, ?, ?, ?)''', params=(user_id, entity_name, site, username, password_encr))
            break
        except ValueError:
            clear()
            input("Please enter an integer to choose the length for the password... ")
        except sqlite3.IntegrityError:
            clear()
            input("Entered Entity Name is already used. Please try to use something different! ")
        except (KeyboardInterrupt, EOFError):
            clear()
            break
            input("Please press enter to continue... ")


def copy_login(key, password_encr):
    clear()
    f = Fernet(base64.urlsafe_b64encode(key))
    try:
        pyperclip.copy(f.decrypt(password_encr).decode("utf-8"))
        print("Password copied!")
        time.sleep(8)
        pyperclip.copy('')
    except KeyboardInterrupt:
        pyperclip.copy('')
        input("Please press enter to continue... ")


def delete_login(entity_name):
    clear()
    ays = input("Are you sure that you want to delete this? Ones deleted, you will not be able to recover this(y/n): ")
    if ays.lower() == "y":
        enterDELETE = input("Please enter \"DELETE\": ")
        if enterDELETE == "DELETE":
            db.run_change('''DELETE FROM logins WHERE entity_name = ?''', params=(entity_name,))
        return
    return


def edit_login(key, entity_name):
    clear()
    print(edit_msg)
    new_entity_name = input("Entity Name: ")
    new_site = input("Site: ")
    new_username = input("Username: ")
    new_password_len = input("Password Length: ")

    ays = input("Are you sure that you want to apply these changes? Ones applied, you will not be able to revert this(y/n): ")
    if ays == "n":
        return

    if new_entity_name != "":
        db.run_change('''UPDATE logins SET entity_name = ? WHERE entity_name = ?''', params=(new_entity_name, entity_name))
    if new_site != "":
        db.run_change('''UPDATE logins SET site_name = ? WHERE entity_name = ?''', params=(new_site, entity_name))
    if new_username != "":
        db.run_change('''UPDATE logins SET username = ? WHERE entity_name = ?''', params=(new_username, entity_name))
    if new_password_len != "":
        password = password_gen(int(new_password_len))
        f = Fernet(base64.urlsafe_b64encode(key))
        password_encr = f.encrypt(password.encode())
        db.run_change('''UPDATE logins SET password_encr = ? WHERE entity_name = ?''', params=(password_encr, entity_name))


def find_login(key):
    while True:
        clear()
        try:
            site = input("Please enter the site name you are looking for: ")
            query = db.run_query('''SELECT entity_name, site_name, username FROM logins WHERE site_name LIKE ?''', params=(f"%{site}%",))
            headers = ["Entity Name", "Site", "Username"]
            print(tabulate(query, headers=headers, tablefmt="pretty"))
            for x,y in find_opt.items():
                if x == ".":
                    print(f"{y} \"{x}\"")
                else:
                    print(f"{x}. {y}")
            find_choice = input("Please choose an option: ")
            match find_choice:
                case "1":
                    entity_name = input("Please choose an entry(Entity Name): ")
                    clear()
                    query = db.run_query('''SELECT site_name, username, password_encr FROM logins WHERE entity_name = ?''', params=(entity_name,))
                    site, username, password_encr = query[0]
                    while True:
                        clear()
                        print(f"Site: {site}\nUsername: {username}\n")

                        for x, y in find_action.items():
                            if x == ".":
                                print(f"{y} \"{x}\"")
                            else:
                                print(f"{x}. {y}")

                        find_action_choice = input("Please choose an action: ")

                        match find_action_choice:
                            case "1":
                                copy_login(key, password_encr)
                            case "2":
                                delete_login(entity_name)
                                break
                            case "3":
                                edit_login(key, entity_name)
                                break
                            case ".":
                                break
                            case _:
                                input("Please choose an option!!! ")
                case "2":
                    continue
                case ".":
                    break
                case _:
                    clear()
                    input("Please choose an option!!! ")
        except IndexError:
            clear()
            input("It seems entered label does not exist... ")
        except KeyboardInterrupt:
            break
        except ValueError:
            clear()
            input("Please enter an integer to choose the length for the password... ")


def master_auth():
    while True:
        clear()
        username = input("Username: ")
        password = getpass.getpass()
        try:
            query = db.run_query('''SELECT id, password_hash FROM users WHERE username = ?''', params=(username,))
            user_id, stored_pwd = query[0]
            ph.verify(stored_pwd, password)
            key = derive_key(username, password)
            return user_id, key
            break
        except IndexError:
            input("Username does not exist. Please try again... ")
        except argon2.exceptions.VerifyMismatchError:
            input("Password is incorrect. Please try again... ")


def main():
    clear()
    master_exists = check_master_user()
    if master_exists is False:
        print("Please create a Master User")
        create_master_user()
        clear()
    try:
        user_id, encr_key = master_auth()
    except (KeyboardInterrupt, EOFError):
        clear()
        exit()
    while True:
        clear()
        print(welcome_msg)
        for key,val in opt.items():
            if key == ".":
                print(f"\n{val} {key}\n")
            else:
                print(f"{key}. {val}")
        choice = input("Please choose: ")
        match choice:
            case "1":
                clear()
                create_login(user_id, encr_key)
                input("Please press enter to continue... ")
            case "2":
                clear()
                find_login(encr_key)
            case ".":
                clear()
                break
            case _:
                clear()
                input("You have to choose smth... ")


if __name__ == "__main__":
    main()
