# SecureVault

**SecureVault** is a Python-based password manager built with **Tkinter** and **cryptography**. It allows you to safely store and manage your passwords in an encrypted local database. The app features master password protection, a recovery key, encrypted vault entries, and password generation functionality.

---

## Features

- Master password authentication
- Recovery key with QR code for account recovery
- Encrypted password vault using **Fernet** symmetric encryption
- Add, view, delete vault entries
- Random password generation
- Copy username or password to clipboard
- Scrollable and organized vault display with table view

---

## Demo / Screenshots

*Add screenshots of your running application here. Example:*

![Vault Screen](screenshots/vault.png)  
*SecureVault main interface displaying stored entries.*

![Recovery QR](screenshots/recovery_qr.png)  
*Recovery key displayed as a QR code.*

---

## Installation

1. Clone this repository:

git clone https://github.com/YOURUSERNAME/securevault.git

2.	Navigate to the project directory:

cd securevault

3.	Install required Python libraries:

pip install cryptography pyperclip qrcode pillow

4.	Run the application:

python securevault.py


Usage
	1.	First Time Setup
	•	Create a master password
	•	Save the recovery key (or scan the QR code)
	2.	Login
	•	Enter your master password to access your vault
	•	If you forget your password, use the recovery key to reset it
	3.	Vault Management
	•	Add new entries with website, username, and password
	•	Delete entries as needed
	•	Use the password generator for strong passwords

⸻

Security
	-	All passwords are stored encrypted in a local SQLite database
	-	Master password uses SHA256 hashing
	-	Vault entries are encrypted with Fernet symmetric encryption
	-	Recovery key ensures account can be restored if master password is lost

