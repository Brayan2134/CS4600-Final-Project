"""
Sender Program
--------------
DESC: This program simulates a sender in a secure communication system.
It encrypts a plaintext message using AES, encrypts the AES key with the receiver's RSA public key,
and authenticates the message with a MAC (HMAC-SHA256).

FOR WHOM:
  - This script represents the "sender" in a sender-receiver secure messaging scenario.

PURPOSE IN PROJECT:
  - To prepare and transmit encrypted data to the receiver in a file-based simulation.
  - The encrypted message, encrypted AES key, and MAC are saved together in `transmitted_data.json`.

HOW IT FITS IN THE FLOW:
  1. Run generate_keys.py first to generate RSA keys.
  2. Run sender.py to encrypt and transmit a message to the receiver.
  3. Receiver will later read and decrypt the transmission using receiver.py.

PREREQUISITE:
  Requires receiver_public.pem from generate_keys.py.

Output folder: /data/
Creates a file: transmitted_data.json
"""

import base64
import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

# === Helper Functions ===


"""
Requirement 2: Each party’s message (from a .txt file) is encrypted using AES before sending it to another party.

Implementation:
                1. get_plaintext_input() allows the user to either load a message from a .txt file or enter it manually.
                2. generate_aes_key(256) creates a 256-bit AES key using get_random_bytes(32).
                3. encrypt_message_with_aes(plaintext, aes_key) encrypts the plaintext using AES in CBC mode.
                4. pad(data, block_size=16) applies PKCS7 padding to align the message with AES block size.
"""
def get_plaintext_input():
    """
    DESC: Prompt user for plaintext input (file or manual typing).
    PRE-COND: None.
    POST-COND: Returns plaintext as a string.
    NOTES: Defaults to manual input if invalid choice is made.
    """
    choice = input("Select input method:\n[1] Load from file\n[2] Enter manually\nChoice: ")
    if choice == '1':
        filepath = input("Enter path to plaintext file (e.g., digest/message.txt): ")
        with open(filepath, 'r', encoding='utf-8') as f:
            plaintext = f.read()
    elif choice == '2':
        plaintext = input("Enter your message: ")
    else:
        print("Invalid choice. Defaulting to manual input.")
        plaintext = input("Enter your message: ")
    return plaintext

def generate_aes_key(length_bits=256):
    """
    DESC: Generate a random AES key.
    PRE-COND: length_bits must be a multiple of 8.
    POST-COND: Returns AES key as bytes.
    NOTES: Default is 256-bit AES key (32 bytes).
    """
    length_bytes = length_bits // 8
    return get_random_bytes(length_bytes)


def encrypt_message_with_aes(plaintext, aes_key):
    """
    DESC: Encrypt plaintext using AES (CBC mode).
    PRE-COND: plaintext must be a string, aes_key must be bytes of correct length.
    POST-COND: Returns IV and encrypted message as bytes.
    NOTES: IV is prepended to ciphertext for easy decryption later.
    """
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv
    padded_plaintext = pad(plaintext.encode('utf-8'))
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext


def pad(data, block_size=16):
    """
    DESC: Apply PKCS7 padding to data.
    PRE-COND: data must be bytes.
    POST-COND: Returns padded data.
    NOTES: Padding bytes are all the same value equal to the padding length.
    """
    padding_length = block_size - len(data) % block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding


"""
Requirement 3: The AES key used is encrypted using the receiver’s RSA public key.
               The encrypted AES key is sent with the encrypted message.

Implementation:
                1. load_receiver_public_key(filepath) reads and loads the receiver's RSA public key from PEM format.
                2. encrypt_aes_key_with_rsa(aes_key, rsa_public_key) encrypts the AES key using RSA and OAEP padding.
                3. The encrypted AES key is written to transmitted_data.json alongside the encrypted message.
"""
def load_receiver_public_key(filepath):
    """
    DESC: Load receiver's RSA public key from a file.
    PRE-COND: File must exist and contain a valid RSA public key.
    POST-COND: Returns an RSA public key object.
    NOTES: If file is missing or corrupted, will raise an exception.
    """
    with open(filepath, 'rb') as f:
        public_key = RSA.import_key(f.read())
    return public_key


def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    """
    DESC: Encrypt AES key using RSA public key (OAEP).
    PRE-COND: aes_key must be bytes, rsa_public_key must be valid.
    POST-COND: Returns encrypted AES key as bytes.
    NOTES: RSA encryption can fail if key sizes are mismatched.
    """
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key


"""
Requirement 4: Message authentication code should be appended to data transmitted.

Implementation:
                1. generate_mac(data, mac_key) uses HMAC-SHA256 to generate a MAC over (encrypted AES key + encrypted message).
                2. save_transmitted_data(encrypted_aes_key, encrypted_message, mac, output_file)
                   encodes all values in Base64 and saves them to transmitted_data.json.
"""
def generate_mac(data, mac_key):
    """
    DESC: Generate HMAC for data authentication.
    PRE-COND: data and mac_key must be bytes.
    POST-COND: Returns MAC as bytes.
    NOTES: MAC key is the same as AES key here for simplicity.
    """
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(data)
    return h.digest()


def save_transmitted_data(encrypted_aes_key, encrypted_message, mac, output_file):
    """
    DESC: Save encrypted AES key, encrypted message, and MAC to a JSON file.
    PRE-COND: All inputs must be bytes; output_file must be a valid path.
    POST-COND: Creates/overwrites a file with encoded transmission data.
    NOTES: Uses base64 encoding for safe JSON storage.
    """
    package = {
        'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
        'encrypted_message': base64.b64encode(encrypted_message).decode('utf-8'),
        'mac': base64.b64encode(mac).decode('utf-8')
    }
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(package, f, indent=4)


# === Main Sender Flow ===

def main():
    """
    DESC: Orchestrates the sending process: input, encryption, MAC, save.
    PRE-COND: None.
    POST-COND: Saves encrypted transmission to a file.
    NOTES: Assumes key files exist at predefined locations.
    """
    plaintext = get_plaintext_input()

    receiver_public_key = load_receiver_public_key('keys/receiver_public.pem')

    aes_key = generate_aes_key(256)

    encrypted_message = encrypt_message_with_aes(plaintext, aes_key)
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, receiver_public_key)

    # Generate MAC over encrypted AES key + encrypted message
    mac_input = encrypted_aes_key + encrypted_message
    mac = generate_mac(mac_input, aes_key)

    save_transmitted_data(encrypted_aes_key, encrypted_message, mac, 'data/transmitted_data.json')

    print("\n[+] Encryption Process Summary:")
    print(f"[Sender] Plaintext: {plaintext}")
    print(f"[Sender] Encrypted AES Key (base64): {base64.b64encode(encrypted_aes_key).decode()}")
    print(f"[Sender] Encrypted Message (base64): {base64.b64encode(encrypted_message).decode()}")
    print(f"[Sender] MAC (base64): {base64.b64encode(mac).decode()}")

    print("\n[+] Message encrypted and transmitted successfully!")


if __name__ == "__main__":
    main()
