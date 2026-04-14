# PassVault 🔐

PassVault is a simple desktop password manager built with Python and Tkinter. It securely stores login credentials in a local encrypted vault protected by a master password.

---

## Features

- Master password protection
- Encrypted local storage for all saved credentials
- Add, view, and delete login entries
- One-click password copy to clipboard
- Built-in password generator
- Password strength checker with visual feedback
- Simple desktop GUI (no internet required)

---

## How it works

PassVault uses a master password to derive an encryption key. That key is used to lock and unlock your vault file. Even if someone accesses the saved file, it remains unreadable without the correct password.

Passwords are never stored in plain text outside of the encrypted vault.

---

## Requirements

- Python 3.x  
- tkinter 
- bcrypt  
- cryptography  

### Install dependencies

```bash
pip install bcrypt cryptography
python passvault.py
