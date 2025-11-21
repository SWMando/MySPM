import os
import sys
import re
import string
import secrets # https://www.geeksforgeeks.org/python/secrets-python-module-generate-secure-random-numbers/
import time
import threading
import base64
import getpass # https://www.geeksforgeeks.org/python/getpass-and-getuser-in-python-password-without-echo/
import platform
import pyperclip
import logging
import sqlite3 # https://www.geeksforgeeks.org/python/python-sqlite-cursor-object/
from tabulate import tabulate
import argon2
import argon2.exceptions
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# General understanding of the difference between hashing and encryption https://pagorun.medium.com/password-encryption-in-python-securing-your-data-9e0045e039e1

# Input validation, try-except: https://www.geeksforgeeks.org/python/input-validation-in-python/

### Global variables
welcome_msg = "Welcome to the My$PM!\n\nTHE APPLICATION SESSION STARTED, IT WILL END IN 15 MINUTES!"
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

# For Input Sanitization
MAX_USERNAME = 64
MAX_ENTITY_NAME = 64
MAX_SITE_NAME = 253
MAX_MASTER_PASSWORD = 64

ENTITY_RE = re.compile(rf"^[A-Za-z0-9_.\- ]{{1,{MAX_ENTITY_NAME}}}$")
SITE_RE = re.compile(rf"^[A-Za-z0-9._:/@+\- ]{{1,{MAX_SITE_NAME}}}$")
USERNAME_RE = re.compile(rf"^[A-Za-z0-9_.@+\-]{{1,{MAX_USERNAME}}}$")
MASTER_PASSWORD_RE = re.compile(fr"^[A-Za-z0-9!@#$%\^&*\-_=+\.,<>?]{{1,{MAX_MASTER_PASSWORD}}}$")

#ENTITY_RE = re.compile(r"^[A-Za-z0-9_\-\. ]{1,%d}$" % MAX_ENTITY_NAME)   # letters, digits, _, -, ., space
#SITE_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")  # basic domain check
#USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@+\-]{1,%d}$" % MAX_USERNAME)  # allow email like chars

# For Argon2ID
time_cost = 2          # Number of iterations
memory_cost = 102400   # 100 MB in KiB
parallelism = 8        # Number of parallel threads
hash_len = 32          # Length of the hash in bytes
salt_len = 16          # Length of the salt in bytes

# class
class DB:
    def __init__(self):
        self.db = 'Vault/Vault.db'
        self.permission = 0o600
        if not os.path.exists(self.db):
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
            os.chmod(self.db, self.permission)

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


# Essential Directories
mode = 0o700
logDir = 'myspm_logs'
vaultDir = 'Vault'
if not os.path.exists(logDir):
    os.mkdir(logDir, mode)

if not os.path.exists(vaultDir):
    os.mkdir(vaultDir, mode)

# Logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
log_format = logging.Formatter(
    "{asctime} {levelname} {message}",
    datefmt='%b %d %H:%M:%S',
    style='{'
)
file_handler = logging.FileHandler('myspm_logs/mng.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(log_format)

logger.addHandler(file_handler)

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
class EmptyInput(Exception):
    def __init__(self):
        self.message = "Error Emptry Input! Please enter something!"
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"

class LongEntityName(Exception):
    def __init__(self):
        self.message = f"Error Long Input! Your input exceeds the limit of {MAX_ENTITY_NAME}!"
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"

class LongSiteName(Exception):
    def __init__(self):
        self.message = f"Error Long Input! Your input exceeds the limit of {MAX_SITE_NAME}!"
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"

class LongUsername(Exception):
    def __init__(self):
        self.message = f"Error Long Input! Your input exceeds the limit of {MAX_USERNAME}!"
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"

class LongMasterPassword(Exception):
    def __init__(self):
        self.message = f"Error Long Input! Your input exceeds the limit of {MAX_MASTER_PASSWORD}!"
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"

class InvalidEntityInput(Exception):
    def __init__(self):
        self.message = "Invalid Entity Name: contains disallowed characters!"
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"

class InvalidSiteInput(Exception):
    def __init__(self):
        self.message = "Invalid Site Name: contains disallowed characters!"
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"

class InvalidUsernameInput(Exception):
    def __init__(self):
        self.message = "Invalid Username: contains disallowed characters!"
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"

class InvalidMasterPassInput(Exception):
    def __init__(self):
        self.message = "Invalid Master Password: contains disallowed characters!"
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------
def clear():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")


def entity_name_sanitize(userinput: str):
    if userinput == "":
        raise EmptyInput()
    if len(userinput) > MAX_ENTITY_NAME:
        raise LongEntityName()
    if ENTITY_RE.fullmatch(userinput) is None:
        raise InvalidEntityInput()

    return userinput


def site_sanitize(userinput: str):
    if userinput == "":
        raise EmptyInput()
    if len(userinput) > MAX_SITE_NAME:
        raise LongSiteName()
    if SITE_RE.fullmatch(userinput) is None:
        raise InvalidSiteInput()

    return userinput


def username_sanitize(userinput: str):
    if userinput == "":
        raise EmptyInput()
    if len(userinput) > MAX_USERNAME:
        raise LongUserName()
    if USERNAME_RE.fullmatch(userinput) is None:
        raise InvalidUsernameInput()

    return userinput


def password_sanitize(userinput: str):
    if userinput == "":
        raise EmptyInput()
    if len(userinput) > MAX_MASTER_PASSWORD:
        raise LongMasterPassword()
    if MASTER_PASSWORD_RE.fullmatch(userinput) is None:
        raise InvalidMasterPassInput()

    return userinput


def check_master_user():
    check = db.run_query('''SELECT COUNT(username) FROM users''')
    if check[0][0] == 0:
        return False
    else:
        return True


def create_master_user():
    while True:
        try:
            username = input("Please enter your username: ").strip()
            password = input("Please enter your password: ").strip()
            logger.info("Sanitizing Username")
            master_user_sanititzed = username_sanitize(username)
            logger.info("Sanitizing Password")
            master_password_sanitized = password_sanitize(password)
            break
        except (KeyboardInterrupt, EOFError):
            clear()
            logger.debug("User left the program while creating Master User account")
            print("Leaving the program")
            sys.exit(0)
        except sqlite3.OperationalError:
            clear()
            logger.critical("Vault was not accessible! Possibly the Vault file was not found!")
            print("Please check the if the Vault was altered! It seems that it was removed")
            os._exit(1)
        except MemoryError:
            clear()
            logger.critical("Memory was overloaded! Possibly there was a long input from the USER!")
            input(f"Memory Overload Error! Please press enter to continue... ")
            os._exit(1)
        except (EmptyInput, LongUsername, LongMasterPassword, InvalidUsernameInput, InvalidMasterPassInput) as e:
            clear()
            logger.error(e)
            input(f"{e}. Please press enter to continue... ")

    logger.info("Hashing the password")
    password_hash = hash_password(master_password_sanitized)
    salt = os.urandom(16)
    logger.info("Uploading newly created Master User to the Database")
    db.run_change('''INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?) ''', params=(master_user_sanititzed, password_hash, salt))
    logger.info("Master User created successfully!")


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
            entity_name = input("Please give a short and unique name for the entry: ").strip()
            site = input("Please enter the site: ").strip()
            username = input("Please enter the username: ").strip()
            length = input("Please enter password length(10-22): ").strip()
            if length == "":
                length = 10
            if int(length) < 10 or int(length) > 22:
                length = 10
            password = password_gen(int(length))
            # Fernet algorythm code snipplet reference: https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
            # https://stackoverflow.com/questions/27335726/how-do-i-encrypt-and-decrypt-a-string-in-python
            f = Fernet(base64.urlsafe_b64encode(key))
            password_encr = f.encrypt(password.encode())
            logger.info("Sanitizing the entity name")
            entity_name_sanitized = entity_name_sanitize(entity_name)
            logger.info("Sanitizing the site name")
            site_sanitized = site_sanitize(site)
            logger.info("Sanitizing the username")
            username_sanitized = username_sanitize(username)
            logger.info("Uploading the new login to the Database")
            db.run_change('''INSERT INTO logins (user_id, entity_name, site_name, username, password_encr) VALUES (?, ?, ?, ?, ?)''', params=(user_id, entity_name_sanitized, site_sanitized, username_sanitized, password_encr))
            break
        except ValueError:
            clear()
            logger.error("User tried passing non integer type to password length input")
            input("Please enter an integer to choose the length for the password... ")
        except sqlite3.IntegrityError:
            clear()
            logger.error("User tried using entity name which already exists")
            input("Entered Entity Name is already used. Please try to use something different! ")
        except sqlite3.OperationalError:
            clear()
            logger.critical("Vault was not accessible! Possibly the Vault file was not found!")
            print("Please check the if the Vault was altered! It seems that it was removed")
            sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            clear()
            logger.debug("Leaving create_login function")
            break
        except MemoryError:
            clear()
            logger.critical("Memory was overloaded! Possibly there was a long input from the USER!")
            input(f"Memory Overload Error! Please press enter to continue... ")
            os._exit(1)
        except (EmptyInput, LongEntityName, LongSiteName, LongUsername) as e:
            clear()
            logger.error(e)
            input(f"{e}. Please press enter to continue... ")
        except (InvalidEntityInput, InvalidSiteInput, InvalidUsernameInput) as e:
            clear()
            logger.error(e)
            input(f"{e}. Please press enter to continue... ")


def copy_login(key, password_encr):
    clear()
    f = Fernet(base64.urlsafe_b64encode(key))
    try:
        pyperclip.copy(f.decrypt(password_encr).decode("utf-8"))
        logger.info("Password copied to clipboard, starting 8 second counter")
        print("Password copied!")
        time.sleep(8)
        pyperclip.copy('')
        logger.info("Clipboard cleared. End of 8 second counter")
    except (KeyboardInterrupt, EOFError):
        logger.warning("User stopped the process, clearing the keyboard")
        pyperclip.copy('')
        input("Please press enter to continue... ")


def delete_login(entity_name):
    clear()
    try:
        logger.info("Asking whether user is sure with the deletion")
        ays = input("Are you sure that you want to delete this? Ones deleted, you will not be able to recover this(y/n): ")
        if ays.lower() == "y":
            logger.info("Asking user to enter DELETE to confirm")
            enterDELETE = input("Please enter \"DELETE\": ")
            if enterDELETE == "DELETE":
                logger.info("Deleting login from the Database")
                db.run_change('''DELETE FROM logins WHERE entity_name = ?''', params=(entity_name,))
            return
        return
    except sqlite3.OperationalError:
        clear()
        logger.critical("Vault was not accessible! Possibly the Vault file was not found!")
        print("Please check the if the Vault was altered! It seems that it was removed")
        sys.exit(1)
    except MemoryError:
        clear()
        logger.critical("Memory was overloaded! Possibly there was a long input from the USER!")
        input(f"Memory Overload Error! Please press enter to continue... ")
        os._exit(1)


def edit_login(key, entity_name):
    while True:
        clear()
        try:
            print(edit_msg)
            new_entity_name = input("Entity Name: ").strip()
            new_site = input("Site: ").strip()
            new_username = input("Username: ").strip()
            new_password_len = input("Password Length: ").strip()

            ays = input("Are you sure that you want to apply these changes? Ones applied, you will not be able to revert this(y/n): ")
            if ays == "n":
                return


            if new_entity_name != "":
                logger.info("Sanitizing the new entity name")
                new_entity_sanitized = entity_name_sanitize(new_entity_name)
                logger.info("Applying entity name change")
                db.run_change('''UPDATE logins SET entity_name = ? WHERE entity_name = ?''', params=(new_entity_sanitized, entity_name))
            if new_site != "":
                logger.info("Sanitizing the new site name")
                new_site_name = site_name_sanitize(new_site)
                logger.info("Applying site name change")
                db.run_change('''UPDATE logins SET site_name = ? WHERE entity_name = ?''', params=(new_site_sanitized, entity_name))
            if new_username != "":
                logger.info("Sanitizing the new username")
                new_username_sanitized = username_sanitize(new_username)
                logger.info("Applying username change")
                db.run_change('''UPDATE logins SET username = ? WHERE entity_name = ?''', params=(new_username_sanitized, entity_name))
            if new_password_len != "":
                if int(new_password_len) < 10 or int(new_password_len) > 22:
                    length = 10
                password = password_gen(int(new_password_len))
                f = Fernet(base64.urlsafe_b64encode(key))
                password_encr = f.encrypt(password.encode())
                logger.info("Applying password change")
                db.run_change('''UPDATE logins SET password_encr = ? WHERE entity_name = ?''', params=(password_encr, entity_name))
        except sqlite3.OperationalError:
            clear()
            logger.critical("Vault was not accessible! Possibly the Vault file was not found!")
            print("Please check the if the Vault was altered! It seems that it was removed")
            sys.exit(1)
        except MemoryError:
            clear()
            logger.critical("Memory was overloaded! Possibly there was a long input from the USER!")
            input(f"Memory Overload Error! Please press enter to continue... ")
            os._exit(1)
        except (EmptyInput, LongEntityName, LongSiteName, LongUsername) as e:
            clear()
            logger.error(e)
            input(f"{e}. Please press enter to continue... ")
        except (InvalidEntityInput, InvalidSiteInput, InvalidUsernameInput) as e:
            clear()
            logger.error(e)
            input(f"{e}. Please press enter to continue... ")


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
                    logger.debug("User opened a login entry")
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
                    logger.debug("User left find_login function")
                    break
                case _:
                    clear()
                    input("Please choose an option!!! ")
        except IndexError:
            clear()
            input("It seems entered label does not exist... ")
        except (KeyboardInterrupt, EOFError):
            logger.debug("User left find_login function")
            break
        except ValueError:
            clear()
            input("Please enter an integer to choose the length for the password... ")
        except MemoryError:
            clear()
            logger.critical("Memory was overloaded! Possibly there was a long input from the USER!")
            input(f"Memory Overload Error! Please press enter to continue... ")
            os._exit(1)
        except sqlite3.OperationalError:
            clear()
            logger.critical("Vault was not accessible! Possibly the Vault file was not found!")
            print("Please check the if the Vault was altered! It seems that it was removed")
            sys.exit(1)


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
        except MemoryError:
            clear()
            logger.critical("Memory was overloaded! Possibly there was a long input from the USER!")
            input(f"Memory Overload Error! Please press enter to continue... ")
            os._exit(1)
        except argon2.exceptions.VerifyMismatchError:
            input("Password is incorrect. Please try again... ")
    
    logger.info("Master User Successful Login!")

def session_limit(timeout, stop_timer):
    start_time = time.time()
    while not stop_timer.is_set():
        if time.time() - start_time > timeout:
            clear()
            logger.info("Session expired due to timeout. Exiting My$PM")
            print("Session timeout!")
            os._exit(0)
        time.sleep(1)

def db_watchdog(db_path, stop_event):
    while not stop_event.is_set():
        if not os.path.exists(db_path):
            clear()
            logger.critical("Vault was not accessible! Possibly the Vault file was not found!")
            print("CRITICAL ERROR: Vault file missing!\n"
                  "The password database cannot be found.\n"
                  "Exiting immediately for security.")
            os._exit(1)   # force-quit for security
        time.sleep(1)  # small interval, low CPU

def main():
    while True:
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
            sys.exit(0)

        SESSION_TIMEOUT = 900
        stop_event = threading.Event()
        timer_thread = threading.Thread(
                target=session_limit,
                daemon=True,
                args=(SESSION_TIMEOUT, stop_event)
        )
        timer_thread.start()
        watchdog_thread = threading.Thread(
                target=db_watchdog,
                daemon=True,
                args=(db.db, stop_event)
        )
        watchdog_thread.start()

        try:
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
                    case "2":
                        clear()
                        find_login(encr_key)
                    case ".":
                        clear()
                        break
                    case _:
                        clear()
                        input("You have to choose smth... ")
        except (KeyboardInterrupt, EOFError):
            clear()
            break
        except MemoryError:
            clear()
            logger.critical("Memory was overloaded! Possibly there was a long input from the USER!")
            input(f"Memory Overload Error! Please press enter to continue... ")
            os._exit(1)
        finally:
            stop_event.set()
            timer_thread.join(timeout=1)
            watchdog_thread.join(timeout=1)


if __name__ == "__main__":
    main()
