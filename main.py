import argparse
import logging
import time
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes cryptographic code for potential timing vulnerabilities.")
    parser.add_argument("operation", choices=["compare_strings", "hmac_verify", "aes_cbc_encrypt", "pbkdf2_derive"],
                        help="The cryptographic operation to analyze.")
    parser.add_argument("--num_runs", type=int, default=100,
                        help="Number of times to run the operation for timing analysis.")
    parser.add_argument("--string1", type=str, default="test_string",
                        help="First string for string comparison.")
    parser.add_argument("--string2", type=str, default="test_string",
                        help="Second string for string comparison.")
    parser.add_argument("--message", type=str, default="This is a test message.",
                        help="Message for HMAC or AES operations.")
    parser.add_argument("--key", type=str, default="secret_key",
                        help="Key for HMAC or AES operations.")
    parser.add_argument("--password", type=str, default="password", help="Password for PBKDF2 operation.")
    parser.add_argument("--salt", type=str, default="salt", help="Salt for PBKDF2 operation.")
    return parser.parse_args()

def compare_strings_timing(string1, string2, num_runs):
    """
    Compares two strings and measures the execution time.
    Simulates a vulnerable string comparison that exits early on mismatch.
    """
    times = []
    for _ in range(num_runs):
        start_time = time.perf_counter()
        result = compare_strings_vulnerable(string1, string2)
        end_time = time.perf_counter()
        times.append(end_time - start_time)

    average_time = sum(times) / len(times)
    logging.info(f"Average time for string comparison: {average_time:.6f} seconds")
    return times

def compare_strings_vulnerable(string1, string2):
    """
    Vulnerable string comparison function.  Exits early on mismatch.
    """
    if len(string1) != len(string2):
        return False
    for i in range(len(string1)):
        if string1[i] != string2[i]:
            return False
    return True

def hmac_verify_timing(message, key, num_runs):
    """
    Verifies an HMAC and measures the execution time.  Simulates a timing leak.
    """
    times = []
    key_bytes = key.encode('utf-8')
    message_bytes = message.encode('utf-8')

    # Generate HMAC
    h = hmac.HMAC(key_bytes, hashes.SHA256(), backend=default_backend())
    h.update(message_bytes)
    hmac_value = h.finalize()

    for _ in range(num_runs):
        start_time = time.perf_counter()
        try:
            h = hmac.HMAC(key_bytes, hashes.SHA256(), backend=default_backend())
            h.update(message_bytes)
            h.verify(hmac_value)
            result = True
        except Exception:
            result = False
        end_time = time.perf_counter()
        times.append(end_time - start_time)

    average_time = sum(times) / len(times)
    logging.info(f"Average time for HMAC verification: {average_time:.6f} seconds")
    return times

def aes_cbc_encrypt_timing(message, key, num_runs):
    """
    Encrypts a message using AES-CBC and measures the execution time.
    """
    times = []
    key_bytes = key.encode('utf-8')
    message_bytes = message.encode('utf-8')

    # Pad the message to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message_bytes) + padder.finalize()

    # Generate a random IV
    iv = secrets.token_bytes(16)

    for _ in range(num_runs):
        start_time = time.perf_counter()
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        end_time = time.perf_counter()
        times.append(end_time - start_time)

    average_time = sum(times) / len(times)
    logging.info(f"Average time for AES-CBC encryption: {average_time:.6f} seconds")
    return times

def pbkdf2_derive_timing(password, salt, num_runs):
    """
    Derives a key using PBKDF2 and measures the execution time.
    """
    times = []
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    for _ in range(num_runs):
        start_time = time.perf_counter()
        try:
             kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=100000,
                backend=default_backend()
             )
             key = kdf.derive(password_bytes)
        except Exception as e:
            logging.error(f"PBKDF2 derivation error: {e}")
            return []
        end_time = time.perf_counter()
        times.append(end_time - start_time)

    average_time = sum(times) / len(times)
    logging.info(f"Average time for PBKDF2 key derivation: {average_time:.6f} seconds")
    return times


def main():
    """
    Main function to parse arguments and run the specified cryptographic operation.
    """
    args = setup_argparse()

    try:
        if args.operation == "compare_strings":
            if not isinstance(args.string1, str) or not isinstance(args.string2, str):
                raise ValueError("String inputs must be strings.")
            compare_strings_timing(args.string1, args.string2, args.num_runs)

        elif args.operation == "hmac_verify":
            if not isinstance(args.message, str) or not isinstance(args.key, str):
                raise ValueError("Message and key must be strings.")
            hmac_verify_timing(args.message, args.key, args.num_runs)

        elif args.operation == "aes_cbc_encrypt":
            if not isinstance(args.message, str) or not isinstance(args.key, str):
                raise ValueError("Message and key must be strings.")
            aes_cbc_encrypt_timing(args.message, args.key, args.num_runs)

        elif args.operation == "pbkdf2_derive":
             if not isinstance(args.password, str) or not isinstance(args.salt, str):
                raise ValueError("Password and salt must be strings.")
             pbkdf2_derive_timing(args.password, args.salt, args.num_runs)

        else:
            logging.error(f"Invalid operation: {args.operation}")

    except ValueError as e:
        logging.error(f"Input error: {e}")
    except Exception as e:
        logging.exception("An unexpected error occurred:")


if __name__ == "__main__":
    """
    Entry point of the script.
    """
    main()