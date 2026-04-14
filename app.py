import tkinter as tk
from tkinter import messagebox
import json, os, base64, bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ── File paths ─────────────────────────────────────────
VAULT_FILE = "vault.enc"
KEY_FILE   = "master.key"

# ── Encryption helpers ─────────────────────────────────
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def save_vault(data: list, key: bytes):
    f = Fernet(key)
    encrypted = f.encrypt(json.dumps(data).encode())
    with open(VAULT_FILE, "wb") as file:
        file.write(encrypted)

def load_vault(key: bytes) -> list:
    if not os.path.exists(VAULT_FILE):
        return []
    with open(VAULT_FILE, "rb") as file:
        encrypted = file.read()
    try:
        f = Fernet(key)
        return json.loads(f.decrypt(encrypted).decode())
    except Exception:
        return None  # wrong password

# ── Master password helpers ────────────────────────────
def save_master(password: str, salt: bytes):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    with open(KEY_FILE, "wb") as file:
        file.write(salt + b"||" + hashed)

def load_master():
    # Returns (salt, hashed_password) or None if no master set
    if not os.path.exists(KEY_FILE):
        return None
    with open(KEY_FILE, "rb") as file:
        parts = file.read().split(b"||")
        return parts[0], parts[1]

def verify_master(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

# ── App state ──────────────────────────────────────────
encryption_key = None
vault_entries  = []

# ── App setup ──────────────────────────────────────────
root = tk.Tk()
root.title("PassVault")
root.geometry("500x450")
root.resizable(False, False)

def clear_screen():
    for widget in root.winfo_children():
        widget.destroy()

# ── First-time setup screen ────────────────────────────
def show_setup():
    clear_screen()

    tk.Label(root, text="PassVault", font=("Helvetica", 24, "bold")).pack(pady=30)
    tk.Label(root, text="Create your master password", font=("Helvetica", 12)).pack()
    tk.Label(root, text="You will use this every time you open the app.",
             font=("Helvetica", 10), fg="gray").pack(pady=4)

    tk.Label(root, text="Master Password", font=("Helvetica", 12)).pack(pady=(15,0))
    pw1 = tk.Entry(root, show="*", font=("Helvetica", 14), width=22)
    pw1.pack(pady=5)
    pw1.focus()

    tk.Label(root, text="Confirm Password", font=("Helvetica", 12)).pack()
    pw2 = tk.Entry(root, show="*", font=("Helvetica", 14), width=22)
    pw2.pack(pady=5)

    status = tk.Label(root, text="", font=("Helvetica", 11), fg="red")
    status.pack(pady=5)

    def create_vault():
        global encryption_key, vault_entries
        p1, p2 = pw1.get(), pw2.get()
        if p1 == "" or p2 == "":
            status.config(text="Please fill in both fields.")
            return
        if p1 != p2:
            status.config(text="Passwords do not match.")
            return
        if len(p1) < 6:
            status.config(text="Password must be at least 6 characters.")
            return

        salt = os.urandom(16)
        save_master(p1, salt)
        encryption_key = derive_key(p1, salt)
        vault_entries = []
        save_vault(vault_entries, encryption_key)
        messagebox.showinfo("Vault Created", "Your vault is ready!")
        show_vault()

    tk.Button(root, text="Create Vault", font=("Helvetica", 13),
              bg="#4CAF50", fg="black", padx=10, pady=6,
              command=create_vault).pack(pady=10)

# ── Login screen ───────────────────────────────────────
def show_login():
    clear_screen()
    global encryption_key, vault_entries
    encryption_key = None
    vault_entries  = []

    tk.Label(root, text="PassVault", font=("Helvetica", 24, "bold")).pack(pady=30)
    tk.Label(root, text="Enter your master password",
             font=("Helvetica", 12), fg="gray").pack()

    pw_entry = tk.Entry(root, show="*", font=("Helvetica", 14), width=22)
    pw_entry.pack(pady=20)
    pw_entry.focus()

    status = tk.Label(root, text="", font=("Helvetica", 11), fg="red")
    status.pack()

    def attempt_login():
        global encryption_key, vault_entries
        entered = pw_entry.get()
        if entered == "":
            status.config(text="Please enter your password.")
            return

        master_data = load_master()
        salt, hashed = master_data

        if not verify_master(entered, hashed):
            status.config(text="Incorrect password.")
            return

        encryption_key = derive_key(entered, salt)
        vault_entries  = load_vault(encryption_key)

        if vault_entries is None:
            status.config(text="Could not decrypt vault. Wrong password?")
            return

        show_vault()

    tk.Button(root, text="Unlock Vault", font=("Helvetica", 13),
              bg="#4CAF50", fg="black", padx=10, pady=6,
              command=attempt_login).pack(pady=10)

# ── Vault screen ───────────────────────────────────────
def show_vault():
    clear_screen()

    top = tk.Frame(root)
    top.pack(fill="x", padx=20, pady=15)
    tk.Label(top, text="Your Vault", font=("Helvetica", 20, "bold")).pack(side="left")
    tk.Button(top, text="+ Add", font=("Helvetica", 11), bg="#2196F3", fg="black",
              padx=8, pady=4, command=show_add_entry).pack(side="right")
    tk.Button(top, text="Lock", font=("Helvetica", 11), bg="#f44336", fg="black",
              padx=8, pady=4, command=show_login).pack(side="right", padx=8)

    if len(vault_entries) == 0:
        tk.Label(root, text="No entries yet. Click + Add to get started.",
                 font=("Helvetica", 11), fg="gray").pack(pady=40)

    for entry in vault_entries:
        draw_entry_row(entry)

def draw_entry_row(entry):
    row = tk.Frame(root, bd=1, relief="solid")
    row.pack(fill="x", padx=20, pady=4)

    info = tk.Frame(row)
    info.pack(side="left", padx=10, pady=8)
    tk.Label(info, text=entry["site"], font=("Helvetica", 13, "bold")).pack(anchor="w")
    tk.Label(info, text=entry["username"], font=("Helvetica", 10), fg="gray").pack(anchor="w")

    def delete_entry(e=entry):
        confirm = messagebox.askyesno("Delete", f"Delete {e['site']}? This cannot be undone.")
        if confirm:
            vault_entries.remove(e)
            save_vault(vault_entries, encryption_key)
            show_vault()

    tk.Button(row, text="Delete", font=("Helvetica", 10),
              bg="#f44336", fg="black", padx=6, pady=3,
              command=delete_entry
              ).pack(side="right", padx=4, pady=8)

    tk.Button(row, text="Copy Password", font=("Helvetica", 10),
              bg="#607D8B", fg="black", padx=6, pady=3,
              command=lambda p=entry["password"]: copy_to_clipboard(p)
              ).pack(side="right", padx=4, pady=8)

def copy_to_clipboard(password):
    root.clipboard_clear()
    root.clipboard_append(password)
    messagebox.showinfo("Copied", "Password copied to clipboard!")

# ── Add entry screen ───────────────────────────────────
def show_add_entry():
    clear_screen()

    tk.Label(root, text="Add New Entry", font=("Helvetica", 20, "bold")).pack(pady=20)

    tk.Label(root, text="Site", font=("Helvetica", 12)).pack()
    site_entry = tk.Entry(root, font=("Helvetica", 13), width=25)
    site_entry.pack(pady=5)

    tk.Label(root, text="Username", font=("Helvetica", 12)).pack()
    username_entry = tk.Entry(root, font=("Helvetica", 13), width=25)
    username_entry.pack(pady=5)

    tk.Label(root, text="Password", font=("Helvetica", 12)).pack()
    pw_entry = tk.Entry(root, font=("Helvetica", 13), width=25, show="*")
    pw_entry.pack(pady=5)

    def generate_password():
        import random
        import string
        characters = string.ascii_letters + string.digits + "!@#$%^&*()_+-=?"
        generated = "".join(random.choice(characters) for _ in range(16))
        pw_entry.delete(0, tk.END)
        pw_entry.insert(0, generated)
        update_strength()

    tk.Button(root, text="Auto-Generate Strong Password", font=("Helvetica", 10),
              bg="#9C27B0", fg="black", padx=6, pady=3,
              command=generate_password).pack(pady=2)

    # Strength bar and label
    strength_label = tk.Label(root, text="Strength", font=("Helvetica", 11), fg="black")
    strength_label.pack()

    strength_bar = tk.Canvas(root, width=200, height=12, bg="#e0e0e0", highlightthickness=0)
    strength_bar.pack(pady=4)

    def analyze_strength(password):
        score = 0
        if len(password) >= 8:  score += 1
        if len(password) >= 12: score += 1
        if len(password) >= 16: score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password): score += 1

        common = ["password", "123456", "qwerty", "abc123", "letmein"]
        if password.lower() in common: score = 0

        return score

    def update_strength(*args):
        password = pw_entry.get()

        if password == "":
            strength_label.config(text="")
            strength_bar.delete("all")
            return

        score = analyze_strength(password)

        if score <= 2:
            rating, color = "Weak", "#f44336"
        elif score <= 4:
            rating, color = "Fair", "#FF9800"
        elif score <= 6:
            rating, color = "Strong", "#2196F3"
        else:
            rating, color = "Very Strong", "#4CAF50"

        fill_width = int((score / 7) * 200)
        strength_bar.delete("all")
        strength_bar.create_rectangle(0, 0, fill_width, 12, fill=color, outline="")
        strength_label.config(text=f"Strength: {rating}", fg=color)

    # Trigger strength check every time the password field changes
    pw_entry.bind("<KeyRelease>", update_strength)

    def save_entry():
        site     = site_entry.get()
        username = username_entry.get()
        password = pw_entry.get()

        if site == "" or username == "" or password == "":
            messagebox.showwarning("Missing Info", "Please fill in all fields.")
            return

        score = analyze_strength(password)
        if score <= 2:
            confirm = messagebox.askyesno(
                "Weak Password",
                "This password is weak. Are you sure you want to save it?"
            )
            if not confirm:
                return

        vault_entries.append({"site": site, "username": username, "password": password})
        save_vault(vault_entries, encryption_key)
        messagebox.showinfo("Saved", f"{site} has been added to your vault!")
        show_vault()

    tk.Button(root, text="Save Entry", font=("Helvetica", 13),
              bg="#4CAF50", fg="black", padx=10, pady=6,
              command=save_entry).pack(pady=15)
    tk.Button(root, text="Cancel", font=("Helvetica", 11), fg="black",
              command=show_vault).pack()

# ── Start the app ──────────────────────────────────────
if load_master() is None:
    show_setup()
else:
    show_login()

root.mainloop()