import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import argparse

# Configure logging
logging.basicConfig(
    filename='encryption_app.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='w'
)

def derive_key(key):
    logging.debug("Deriving key with provided passphrase.")  # DEBUG: Tracking key derivation start
    salt = b'salt1234'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(key)
    logging.debug("Key derivation complete.")  # DEBUG: Tracking key derivation completion
    return derived_key

def encrypt(plaintext, key):
    logging.info("Starting encryption process.")  # INFO: Starting encryption
    key = derive_key(key.encode('utf-8'))
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    encrypted_text = base64.b64encode(ciphertext).decode('utf-8')
    logging.info("Encryption complete.")  # INFO: Encryption complete
    logging.debug("Encrypted text: %s", encrypted_text)  # DEBUG: Output encrypted text
    return encrypted_text

def decrypt(ciphertext, key):
    logging.info("Starting decryption process.")  # INFO: Starting decryption
    key = derive_key(key.encode('utf-8'))
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key[:16]), backend=default_backend())
    decryptor = cipher.decryptor()
    ciphertext_bytes = base64.b64decode(ciphertext)
    plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
    decrypted_text = plaintext.decode('utf-8')
    logging.info("Decryption complete.")  # INFO: Decryption complete
    logging.debug("Decrypted text: %s", decrypted_text)  # DEBUG: Output decrypted text
    return decrypted_text

def main():
    logging.info("Application started.")  # INFO: Application startup
    parser = argparse.ArgumentParser(description="Simple AES Encryption and Decryption")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help='Select "encrypt" or "decrypt" mode')
    parser.add_argument('-p', '--plaintext', help='Text to be encrypted or decrypted')
    parser.add_argument('-k', '--key', help='Encryption/Decryption key')

    args = parser.parse_args()

    if args.mode == 'encrypt':
        if not args.plaintext or not args.key:
            logging.error("Encryption failed: Both plaintext and key are required.")  # ERROR: Missing required inputs
            print("Error: Both plaintext and key are required for encryption.")
            return
        encrypted_text = encrypt(args.plaintext.encode('utf-8'), args.key)
        print(f"Encrypted Text: {encrypted_text}")

    elif args.mode == 'decrypt':
        if not args.plaintext or not args.key:
            logging.error("Decryption failed: Both ciphertext and key are required.")  # ERROR: Missing required inputs
            print("Error: Both ciphertext and key are required for decryption.")
            return
        decrypted_text = decrypt(args.plaintext, args.key)
        print(f"Decrypted Text: {decrypted_text}")

    logging.info("Application finished.")  # INFO: Application shutdown

if __name__ == "__main__":
    main()

