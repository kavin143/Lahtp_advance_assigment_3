# Lahtp_advance_assigment_3

# 🔒 Secure Chat Application

A Python-based **secure chat application** with the following features:

* **User authentication** (Register/Login) stored in MySQL
* **End-to-End Encryption (E2E)** using RSA for key exchange + AES/Fernet for session messages
* **Transport-level encryption** (client ↔ server) using a shared secret key
* **Graphical User Interface (GUI)** built with Tkinter
* **Multi-client chat support** via a threaded TCP server

---

## 📂 Project Structure

```
chat_app/
│── client_app.py         # Tkinter client app with login, register, chat UI
│── server.py             # Multi-threaded chat server
│── conn_db.py            # MySQL connector class (user register/login)
│── create_secret_key.py  # Utility script to generate secret.key
│── secret.key            # Symmetric key for transport-level encryption
│── .env                  # Environment variables (DB credentials)
│── requirements.txt      # Python dependencies
│── rsa_priv_<user>.pem   # Auto-generated RSA private key (per user)
│── rsa_pub_<user>.pem    # Auto-generated RSA public key (per user)
```

---

## ⚙️ Requirements

Create a `requirements.txt` with:

```txt
cryptography==43.0.1
pycryptodome==3.20.0
mysql-connector-python==9.0.0
bcrypt==4.2.0
python-dotenv==1.0.1
pyfiglet==1.0.2
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🛠️ Setup

### 1. Generate a transport secret key

Run once to generate `secret.key`:

```bash
python create_secret_key.py
```

### 2. MySQL Database

Create a database and table:

```sql
CREATE DATABASE chat_app_db;

USE chat_app_db;

CREATE TABLE chat_app (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(150) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);
```

### 3. Configure `.env`

Create a `.env` file in the root:

```env
DB_HOST=localhost
DB_USER=your_mysql_user
DB_PASSWORD=your_mysql_password
DB_NAME=chat_app_db
```

### 4. Run the Server

```bash
python server.py
```

### 5. Run the Client

```bash
python client_app.py
```

Each client logs in/registers and joins the chat.

---

## 🔑 Security Design

* **Transport Encryption (Server ↔ Clients):**

  * Uses a shared `secret.key` (Fernet AES-128) to protect all traffic from eavesdroppers.

* **End-to-End Encryption (Client ↔ Client):**

  * RSA keys generated per user (`rsa_priv_<user>.pem` & `rsa_pub_<user>.pem`)
  * Public keys are exchanged securely via the server
  * Clients use **RSA** to exchange an AES session key (Fernet), then chat messages are encrypted end-to-end

* **Database Security:**

  * User passwords are hashed with **bcrypt** before storage
  * Regex validation prevents SQL injection in usernames

---

## 🖥️ Features

✅ Register/Login with database
✅ Chat with all online users (public)
✅ Start **E2E encrypted private chat** with a selected user
✅ View online users in real-time
✅ Encrypted `.pem` key pairs are automatically generated & reused

---

## 🚀 Future Improvements

* Add **message history** persistence in MySQL
* Implement **group private chats**
* Build **desktop/mobile clients** with PyQt/Flutter

---

## ⚠️ Notes

* Never upload `.env`, `secret.key`, or `.pem` files to GitHub.
* Run server first, then clients.
* For deployment, replace `localhost` with a server IP/hostname.

Sample output:
<img width="1910" height="993" alt="image" src="https://github.com/user-attachments/assets/d89ae9eb-54c5-4fbc-af65-fcf8d3442da2" />

