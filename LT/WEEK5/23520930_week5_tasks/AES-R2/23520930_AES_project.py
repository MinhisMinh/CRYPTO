# -*- coding: utf-8 -*-
import sys, os
sys.path.append(os.getcwd())  # Get current working dir and export to Python paths
from mypackages import key_expansion, modes

def read_file(filename):
    """Read content from a file. Create the file if it does not exist."""
    if not os.path.exists(filename):
        print(f"{filename} not found. Creating a new file with default content.")
        write_file(filename, "Default plaintext message")
    
    with open(filename, 'r', encoding='utf-8') as file:
        return file.read().strip()

def write_file(filename, content):
    """Write content to a file."""
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(content)

def aes_mode_test(mode, plaintext):
    key128 = "12345678abcdefgh"
    key_bytes_128 = key128.encode('utf-8')
    aes_mode = modes.modes(key_bytes_128)

    if mode == "ECB":
        cipher = aes_mode.ecb_encrypt(plaintext)
        decrypt_function = aes_mode.ecb_decrypt
    elif mode == "CBC":
        cipher = aes_mode.cbc_encrypt(plaintext)
        decrypt_function = aes_mode.cbc_decrypt
    elif mode == "CFB":
        cipher = aes_mode.cfb_encrypt(plaintext)
        decrypt_function = aes_mode.cfb_decrypt
    elif mode == "OFB":
        cipher = aes_mode.ofb_encrypt(plaintext)
        decrypt_function = aes_mode.ofb_decrypt
    elif mode == "CTR":
        cipher = aes_mode.ctr_encrypt(plaintext)
        decrypt_function = aes_mode.ctr_decrypt
    else:
        print("Invalid mode!")
        return

    ciphertext_hex = cipher.hex()
    write_file("ciphertext.txt", ciphertext_hex)

    recovered_text = decrypt_function(bytes.fromhex(ciphertext_hex))
    write_file("decrypted.txt", recovered_text)

## Main Part
if __name__ == "__main__":
    print("Select AES mode:")
    print("1. ECB")
    print("2. CBC")
    print("3. CFB")
    print("4. OFB")
    print("5. CTR")
    choice = input("Enter choice (1/2/3/4/5): ")

    mode_map = {
        "1": "ECB",
        "2": "CBC",
        "3": "CFB",
        "4": "OFB",
        "5": "CTR"
    }

    selected_mode = mode_map.get(choice)
    if selected_mode:
        plaintext = read_file("plaintext.txt")
        aes_mode_test(selected_mode, plaintext)
    else:
        print("Invalid choice!")
    