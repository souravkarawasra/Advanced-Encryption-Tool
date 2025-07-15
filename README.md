# ADVANCED ENCRYPTION TOOL


A simple yet powerful Python-based **AES-256 file encryption and decryption tool** with a clean GUI interface and **drag-and-drop support**.

This tool allows users to securely encrypt and decrypt files using strong cryptographic algorithms with password protection — all without writing a single command!

---

## Features

-  AES-256-bit encryption using the `cryptography` library
-  Secure password input and confirmation
-  Drag and Drop file support (via `tkinterdnd2`)
-  Supports any file type (text, image, PDF, etc.)
-  No command-line usage needed — full GUI
-  Cross-platform (Windows/Linux)

---

## How It Works

### **Encryption Process**
1. User selects or drags a file into the GUI.
2. Tool asks for a **password** and **confirmation**.
3. Generates a random **salt** and **IV (Initialization Vector)**.
4. Derives a strong 256-bit AES key using `PBKDF2HMAC` from the password + salt.
5. Encrypts the file using AES in **CFB mode**.
6. Saves the output file as:  


### **Decryption Process**
1. Drag or select a `.enc` file.
2. Enter the password used during encryption.
3. Extracts salt + IV from the encrypted file.
4. Derives the same AES key.
5. Decrypts the file and saves as:  

---

## 🧩 Technologies Used

| Library | Purpose |
|--------|---------|
| `tkinter` | For building the GUI |
| `tkinterdnd2` | Adds drag-and-drop file support |
| `cryptography` | Industry-standard AES encryption |
| `secrets` | Generates random cryptographic values |
| `PBKDF2HMAC` | Derives strong key from password + salt |

---

## Output

<img width="400" height="311" alt="Screenshot 2025-07-15 084210" src="https://github.com/user-attachments/assets/e3616312-4af9-4019-a448-7acabfb42e74" />

<img width="178" height="112" alt="Screenshot 2025-07-15 084224" src="https://github.com/user-attachments/assets/0b7ae66a-bac7-4b58-be61-33258066ddbb" />

<img width="180" height="115" alt="Screenshot 2025-07-15 084300" src="https://github.com/user-attachments/assets/26f7f49c-6942-4fcc-8cd4-ebfeb1d7a7de" />

<img width="400" height="154" alt="Screenshot 2025-07-15 084333" src="https://github.com/user-attachments/assets/ceabc6b5-cb67-4763-b939-ec6a37d4fd2f" />



