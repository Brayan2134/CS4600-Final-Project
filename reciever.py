"""
Receiver Program
----------------
DESC: This program simulates a receiver in a secure communication system.
It loads the encrypted message file created by the sender, verifies its authenticity via MAC,
decrypts the AES key using RSA, and then decrypts the actual message.

FOR WHOM:
  - This script represents the "receiver" in a sender-receiver secure messaging scenario.

PURPOSE IN PROJECT:
  - To simulate the secure reception, decryption, and validation of a transmitted message.

HOW IT FITS IN THE FLOW:
  1. Run generate_keys.py first to generate RSA keys.
  2. Run sender.py to encrypt and transmit a message.
  3. Run receiver.py to decrypt and read the message.

PREREQUISITE:
  Requires receiver_private.pem from generate_keys.py.
  Requires transmitted_data.json created by sender.py.

Output: Displays the original plaintext message.
"""

import os
import base64
import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256

# === Helper Functions ===

def load_receiver_private_key(filepath):
    """
    DESC: Load receiver's RSA private key from a file.
    PRE-COND: File must exist and contain a valid RSA private key.
    POST-COND: Returns an RSA private key object.
    NOTES: If file is missing or corrupted, will raise an exception.
    """
    with open(filepath, 'rb') as f:
        private_key = RSA.import_key(f.read())
    return private_key


def read_transmitted_data(input_file):
    """
    DESC: Read encrypted AES key, encrypted message, and MAC from a JSON file.
    PRE-COND: input_file must exist and be a valid JSON format.
    POST-COND: Returns (encrypted_aes_key, encrypted_message, mac) as bytes.
    NOTES: Assumes base64 encoding in file.
    """
    with open(input_file, 'r', encoding='utf-8') as f:
        package = json.load(f)
    encrypted_aes_key = base64.b64decode(package['encrypted_aes_key'])
    encrypted_message = base64.b64decode(package['encrypted_message'])
    mac = base64.b64decode(package['mac'])
    return encrypted_aes_key, encrypted_message, mac


def decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key):
    """
    DESC: Decrypt AES key using RSA private key (OAEP).
    PRE-COND: encrypted_aes_key must be bytes, rsa_private_key must be valid.
    POST-COND: Returns decrypted AES key as bytes.
    NOTES: RSA decryption can fail if wrong key or corrupted data.
    """
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key


def verify_mac(data, received_mac, mac_key):
    """
    DESC: Verify HMAC for data integrity.
    PRE-COND: data, received_mac, mac_key must be bytes.
    POST-COND: Returns True if MAC valid, False otherwise.
    NOTES: Returns False on verification failure instead of crashing.
    """
    try:
        h = HMAC.new(mac_key, digestmod=SHA256)
        h.update(data)
        h.verify(received_mac)
        return True
    except ValueError:
        return False


def decrypt_message_with_aes(encrypted_message, aes_key):
    """
    DESC: Decrypt encrypted message using AES (CBC mode).
    PRE-COND: encrypted_message must be bytes with IV prepended.
    POST-COND: Returns plaintext as a string.
    NOTES: Expects IV to be first 16 bytes; uses PKCS7 unpadding.
    """
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext)
    return plaintext.decode('utf-8')


def unpad(data, block_size=16):
    """
    DESC: Remove PKCS7 padding from data.
    PRE-COND: data must be bytes.
    POST-COND: Returns unpadded data as bytes.
    NOTES: Assumes correct padding; corrupt padding will cause bugs.
    """
    padding_length = data[-1]
    return data[:-padding_length]


def display_plaintext(plaintext):
    """
    DESC: Output the decrypted plaintext message.
    PRE-COND: plaintext must be a string.
    POST-COND: Prints plaintext to console.
    NOTES: None.
    """
    print("\n[+] Decrypted Message:")
    print(plaintext)


# === Main Receiver Flow ===

def main():
    """
    DESC: Orchestrates the receiving process: load keys, verify, decrypt.
    PRE-COND: None.
    POST-COND: Displays decrypted message if successful.
    NOTES: Aborts if MAC verification fails.
    """
    receiver_private_key = load_receiver_private_key('keys/receiver_private.pem')

    encrypted_aes_key, encrypted_message, received_mac = read_transmitted_data('data/transmitted_data.json')

    aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, receiver_private_key)

    mac_input = encrypted_aes_key + encrypted_message
    if verify_mac(mac_input, received_mac, aes_key):
        plaintext = decrypt_message_with_aes(encrypted_message, aes_key)
        display_plaintext(plaintext)
    else:
        print("[-] MAC verification failed! Message may have been tampered with.")


if __name__ == "__main__":
    main()
