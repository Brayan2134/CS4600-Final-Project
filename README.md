# 🔐 Secure File-Based Communication System

This project implements a basic **end-to-end encrypted communication system** between a sender and a receiver using:

- **RSA** for asymmetric key exchange
- **AES** for symmetric message encryption
- **HMAC-SHA256** for message authentication

There is no real networking — files are used to simulate message transmission.

---

## 📌 How It Works

1. The **Sender** encrypts a message with AES.
2. The AES key is encrypted with the **Receiver's RSA public key**.
3. A **MAC (HMAC)** is generated for authentication.
4. All three (encrypted message, encrypted AES key, MAC) are saved to a JSON file (`transmitted_data.json`).
5. The **Receiver** verifies the MAC, decrypts the AES key with their **private RSA key**, and finally decrypts the message.

---

## 📁 Project Structure

```
project_root/
├── keys/                     # Stores RSA key pairs (generated automatically)
├── data/                     # Stores the transmitted_data.json file
├── utils/
│   └── generate_keys.py      # Script to generate sender and receiver RSA key pairs
├── sender.py                 # Sender program
├── receiver.py               # Receiver program
└── README.md                 # This file
```

---

## ✅ Setup Instructions

### **1. Prerequisite: Install dependencies**
You need Python 3.6+ and `pycryptodome`.

```bash
pip install pycryptodome
```

---

### **2. Step-by-step Execution**

#### **2.a: Generate RSA Key Pairs**
This script will create the necessary RSA keys for both sender and receiver.

```bash
python utils/generate_keys.py
```

You will now see:

```
keys/
├── sender_private.pem
├── sender_public.pem
├── receiver_private.pem
└── receiver_public.pem
```

---

#### **1.b: Create the Message**
You have two options:
- Type your message directly into the terminal when prompted
- OR save it in a file like `digest/message.txt` and input the path

---

#### **2: Run the Sender**
This will encrypt the message, encrypt the AES key, and generate a MAC.

```bash
python sender.py
```

This creates:

```
data/
└── transmitted_data.json
```

---

#### **3: Run the Receiver**
This verifies the MAC, decrypts the AES key, and decrypts the original message.

```bash
python receiver.py
```

If everything works correctly, you will see:

```
[+] Decrypted Message:
Hello, this is a secure message!
```

---

## 🛠️ Optional Notes

- You can regenerate keys at any time by re-running `generate_keys.py`.
- If MAC verification fails, you will see:  
  `[-] MAC verification failed! Message may have been tampered with.`
- Padding is PKCS7, and AES is run in CBC mode.

---

## 🎓 Educational Purpose

This project is a great example of:
- Hybrid encryption
- Cryptographic key management
- Message authentication with HMAC
- Simulated secure file transfer (without sockets)

It follows the basic pattern used in secure messaging, email, and TLS systems.

Feel free to fork, expand, or refactor it for your own use or academic projects!
