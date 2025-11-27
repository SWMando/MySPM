# **My$PM**

Welcome to My$PM!

This is My Secure Password Manager Project for the university course "Secure Programming". My$PM is an open-source project, for people who want a simple Linux terminal based password manager, written in python.

## **Installation**

To install just run:

```shell
git clone https://github.com/SWMando/MySPM.git
```

After installing go to the repo folder:

```shell
cd MySPM/
```

There you will see:

```shell
MySPM
├── LICENSE
├── mng.py
├── README.md
└── requirements.txt
```

Since Python 3.12 and later there is a requirement to run all programs in an environment. To do so create an environment:

Depending on your Linux distribution, install the required packages:

#### **Debian/Ubuntu (APT-based)**

```shell
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

#### **RHEL / Fedora / CentOS (DNF-based)**

```shell
sudo dnf install python3 python3-pip python3.12-venv
```

> Note: On Fedora, venv may already be included with the default Python package.

#### **Arch / Manjaro (Pacman-based)**

```shell
sudo pacman -S python python-pip
```

`venv` is included with Python on Arch-based distros.

To create Python Environment run:

```shell
python3 -m venv <name>
```

`<name>` - this basically the name of your Python environment and you can set whatever you want

To use Python Environment run:

```shell
source <name>/bin/activate
```

And if you want to exit the Python Environment, run:

```shell
deactivate
```

For reassurance, you can upgrade `pip` by running:

```shell
pip install --upgrade pip
```

Then download all the required libraries to run the `My$PM`:

```shell
pip install -r requirements.txt
```

For security purposes be sure that the python file `mng.py` has permissions set to `700`, so that only your user is able to run the program

After installing all dependencies and activating your virtual environment, you can start My$PM using:

```shell
python mng.py
```

Most Linux distributions map `python` to `python3` inside virtual environments.  
If your system does not, simply run:

```shell
python3 mng.py
```
## **Use**

`My$PM` has fairly easy and self-explanatory user interface. Overall you can the following:
- Create Master User
- Log in/Log out
- Creating Login Entry
- Searching Login Entry
- Copying Login Entry password
- Editing Login Entry
- Deleting Login Entry

Since most of the users are using password manager to not remember their passwords by heart, user is not able to use personal password for login entry. That means when creating or editing login entry, user can only choose password length. 

## **About**

During the first run, you will be asked to create a master user. The prompt for password is not hidden so that user is able to to see, so be careful (during login process it is hidden). It will also create two folders `Vault` and `myspm_logs` with permissions `0700`. That means only the user running the program is able to read, write and execute the files and folders.

Contents of the `Vault/` directory should look like this:
```shell
Vault
├── Vault.db
└── Vault.db.hmac
```

The `Vault.db.hmac` is used for integrity check, it basically contains the hash of the database. 

Contents of the `myspm_logs/` directory should look like this:
```shell
myspm_logs
└── mng.log
```

The log size is set to `100 MB` and it saves up to 10 copies. Meaning, when there is a need for 11th log file, it will start to rewrite from file `mng.log.1`.

## **IMPORTANT**

Hash is being created for the database in the very beginning, before and after the change is applied to the database. So if someone tries to manually change the database file using your user, all data is lost. Since the hash will not be the same as in the `Vault.db.hmac` file.

**SO PLEASE BACKUP `Vault.db` AND `Vault.db.hmac`!!!**
