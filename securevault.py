import sqlite3
import hashlib
from tkinter import *
from tkinter import simpledialog, ttk
from functools import partial
import uuid
import pyperclip
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import random
import string
import qrcode
from PIL import Image, ImageTk

# --- Encryption Setup ---
backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = None

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)

# --- Database Setup ---
with sqlite3.connect("securevault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

# --- Utility Functions ---
def hashPassword(password):
    return hashlib.sha256(password).hexdigest()

def popUp(prompt):
    return simpledialog.askstring("Input", prompt)

def generateRandomPassword(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# --- New User Screen ---
def newUserScreen():
    for widget in window.winfo_children():
        widget.destroy()

    Label(window, text="Welcome to SecureVault", font=("Arial", 16)).pack(pady=10)
    Label(window, text="Create Master Password:").pack()
    pw1 = Entry(window, show="*")
    pw1.pack()
    Label(window, text="Confirm Password:").pack()
    pw2 = Entry(window, show="*")
    pw2.pack()

    def saveMasterPassword():
        if pw1.get() != pw2.get():
            Label(window, text="Passwords do not match!", fg="red").pack()
            return
        hashed = hashPassword(pw1.get().encode())
        key_uuid = str(uuid.uuid4().hex)
        recovery = hashPassword(key_uuid.encode())
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(pw1.get().encode()))
        cursor.execute("DELETE FROM masterpassword")
        cursor.execute("INSERT INTO masterpassword(password,recoveryKey) VALUES(?,?)", (hashed, recovery))
        db.commit()
        recoveryScreen(key_uuid)

    Button(window, text="Save", command=saveMasterPassword).pack(pady=5)

# --- Recovery Screen ---
def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    Label(window, text="Save this Recovery Key!").pack(pady=5)
    Label(window, text=key).pack(pady=5)

    # Generate QR code for the key
    qr = qrcode.make(key)
    qr = qr.resize((150, 150))
    qr_img = ImageTk.PhotoImage(qr)
    lbl_qr = Label(window, image=qr_img)
    lbl_qr.image = qr_img
    lbl_qr.pack(pady=5)

    def done():
        passwordVault()

    Button(window, text="Done", command=done).pack(pady=5)

# --- Login Screen ---
def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    Label(window, text="SecureVault Login", font=("Arial", 16)).pack(pady=10)
    Label(window, text="Enter Master Password:").pack()
    pw_entry = Entry(window, show="*")
    pw_entry.pack()
    msg = Label(window)
    msg.pack()

    def checkLogin():
        hashed = hashPassword(pw_entry.get().encode())
        cursor.execute("SELECT * FROM masterpassword WHERE password=?", (hashed,))
        if cursor.fetchall():
            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(pw_entry.get().encode()))
            passwordVault()
        else:
            msg.config(text="Wrong password!", fg="red")
            pw_entry.delete(0, END)

    Button(window, text="Login", command=checkLogin).pack(pady=5)

# --- Vault Screen ---
def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

    Label(window, text="SecureVault", font=("Arial", 16)).pack(pady=10)

    tree = ttk.Treeview(window, columns=("Website", "Username", "Password"), show='headings')
    tree.heading("Website", text="Website")
    tree.heading("Username", text="Username")
    tree.heading("Password", text="Password")
    tree.pack(fill=BOTH, expand=True)

    def refreshTree():
        for row in tree.get_children():
            tree.delete(row)
        cursor.execute("SELECT * FROM vault")
        for item in cursor.fetchall():
            tree.insert("", "end", iid=item[0], values=(decrypt(item[1], encryptionKey), decrypt(item[2], encryptionKey), decrypt(item[3], encryptionKey)))

    refreshTree()

    def addEntry():
        website = encrypt(popUp("Website").encode(), encryptionKey)
        username = encrypt(popUp("Username").encode(), encryptionKey)
        password = encrypt(popUp("Password").encode(), encryptionKey)
        cursor.execute("INSERT INTO vault(website,username,password) VALUES(?,?,?)", (website, username, password))
        db.commit()
        refreshTree()

    def deleteEntry():
        selected = tree.selection()
        if selected:
            cursor.execute("DELETE FROM vault WHERE id=?", (selected[0],))
            db.commit()
            refreshTree()

    Button(window, text="Add Entry", command=addEntry).pack(side=LEFT, padx=5, pady=5)
    Button(window, text="Delete Entry", command=deleteEntry).pack(side=LEFT, padx=5, pady=5)

# --- Initialize App ---
window = Tk()
window.title("SecureVault")
window.geometry("500x400")

cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    newUserScreen()

window.mainloop()
