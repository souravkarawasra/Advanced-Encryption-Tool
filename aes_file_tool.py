import os
import secrets
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.simpledialog import askstring
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# === Constants ===
KEY_LENGTH = 32
SALT_SIZE = 16
IV_SIZE = 16
ITERATIONS = 100000

# === Key Derivation ===
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# === Encrypt File ===
def encrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        salt = secrets.token_bytes(SALT_SIZE)
        iv = secrets.token_bytes(IV_SIZE)
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        output_file = file_path + '.enc'
        with open(output_file, 'wb') as f:
            f.write(salt + iv + encrypted_data)

        messagebox.showinfo("Success", f"Encrypted file saved as:\n{output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed:\n{str(e)}")

# === Decrypt File ===
def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        salt = content[:SALT_SIZE]
        iv = content[SALT_SIZE:SALT_SIZE+IV_SIZE]
        encrypted_data = content[SALT_SIZE+IV_SIZE:]

        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        output_file = file_path.replace('.enc', '.dec')
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", f"Decrypted file saved as:\n{output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")

# === Password Confirmation ===
def get_confirmed_password():
    pwd = askstring("Password", "Enter password:", show='*')
    if not pwd:
        return None
    confirm = askstring("Confirm Password", "Confirm password:", show='*')
    if confirm != pwd:
        messagebox.showerror("Mismatch", "Passwords do not match!")
        return None
    return pwd

# === Event Handlers ===
def handle_encrypt(file_path=None):
    if not file_path:
        file_path = filedialog.askopenfilename()
    if file_path:
        password = get_confirmed_password()
        if password:
            encrypt_file(file_path, password)

def handle_decrypt(file_path=None):
    if not file_path:
        file_path = filedialog.askopenfilename()
    if file_path:
        password = askstring("Password", "Enter password:", show='*')
        if password:
            decrypt_file(file_path, password)

def drop(event):
    file_path = root.tk.splitlist(event.data)[0]
    if file_path.endswith('.enc'):
        handle_decrypt(file_path)
    else:
        handle_encrypt(file_path)

# === GUI Setup ===
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    root = TkinterDnD.Tk()
    root.drop_target_register(DND_FILES)
    root.dnd_bind('<<Drop>>', drop)
except ImportError:
    root = tk.Tk()
    messagebox.showwarning("Drag-and-Drop Disabled", "To enable drag and drop:\n\npip install tkinterdnd2")

root.title("AES-256 File Encryption Tool")
root.geometry("400x280")
root.resizable(False, False)

frame = tk.Frame(root, padx=20, pady=20)
frame.pack(expand=True)

title = tk.Label(frame, text="Secure File Encryption Tool", font=("Arial", 14, "bold"))
title.pack(pady=10)

btn_encrypt = tk.Button(frame, text="Encrypt File", command=handle_encrypt, width=25, height=2, bg="#4CAF50", fg="white")
btn_encrypt.pack(pady=10)

btn_decrypt = tk.Button(frame, text="Decrypt File", command=handle_decrypt, width=25, height=2, bg="#2196F3", fg="white")
btn_decrypt.pack(pady=10)

footer = tk.Label(frame, text="Drag & Drop files to Encrypt/Decrypt", font=("Arial", 10), fg="gray")
footer.pack(pady=10)

root.mainloop()
