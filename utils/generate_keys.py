"""
Generate Keys Script
---------------------
DESC: This script generates RSA key pairs for both the sender and receiver in the secure communication system.

FOR WHOM:
  - Generates keys for both roles:
  - Sender (sender_private.pem, sender_public.pem)
  - Receiver (receiver_private.pem, receiver_public.pem)

PURPOSE IN PROJECT:
  - These RSA keys are essential for the encryption and decryption of AES session keys.
  - The sender uses the receiver's public key to encrypt the AES key.
  - The receiver uses their private key to decrypt it and access the message.

HOW IT FITS IN THE FLOW:
  1. Run this script *first* to generate all RSA keys.
  2. Then run sender.py (uses receiver_public.pem)
  3. Then run receiver.py (uses receiver_private.pem)

PREREQUISITE:
    Yes — this must be run before either sender.py or receiver.py are used.

Output folder: /keys/
Each key is saved in PEM format for secure reuse across the system.
"""

from Crypto.PublicKey import RSA
import os

# === CONFIGURATION ===
KEY_SIZE = 2048
KEY_DIR = "../keys"


"""
Requirement 1: The two parties have each other’s RSA public key.
               Each of them holds his/her own RSA private key.

Implementation:
                1. generate_and_save_keypair(name_prefix) generates RSA key pairs for both sender and receiver.
                2. RSA.generate(KEY_SIZE) creates a 2048-bit RSA key pair.
                3. export_key() exports the private and public keys to PEM format.
                4. Keys are saved to the 'keys/' directory as:
                     - sender_private.pem / sender_public.pem
                     - receiver_private.pem / receiver_public.pem
"""
def generate_and_save_keypair(name_prefix):
    """
    DESC: Generate RSA key pair and save to files.
    PRE-COND: name_prefix is a valid string name (e.g., 'receiver').
    POST-COND: Saves <name_prefix>_private.pem and <name_prefix>_public.pem to the keys/ folder.
    NOTES: Overwrites existing keys with the same name.
    """
    key = RSA.generate(KEY_SIZE)

    private_key = key.export_key()
    public_key = key.publickey().export_key()

    private_path = os.path.join(KEY_DIR, f"{name_prefix}_private.pem")
    public_path = os.path.join(KEY_DIR, f"{name_prefix}_public.pem")

    with open(private_path, 'wb') as priv_file:
        priv_file.write(private_key)

    with open(public_path, 'wb') as pub_file:
        pub_file.write(public_key)

    print(f"[+] Generated keys for '{name_prefix}' and saved to '{KEY_DIR}/'.")


def ensure_key_dir():
    """
    DESC: Ensure the keys directory exists.
    PRE-COND: None.
    POST-COND: Creates the 'keys/' folder if it doesn't exist.
    NOTES: None.
    """
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)


def main():
    """
    DESC: Entry point for key generation script.
    PRE-COND: None.
    POST-COND: Saves RSA key pairs for both sender and receiver.
    NOTES: You can comment out sender/receiver lines if you only need one side.
    """
    ensure_key_dir()
    generate_and_save_keypair("receiver")
    generate_and_save_keypair("sender")


if __name__ == "__main__":
    main()
