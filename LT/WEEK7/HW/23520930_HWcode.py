import secrets
import base64
import sys, os
sys.path.append(os.getcwd()) # get curent working dir and export to python paths
from mypackages import key_expansion,modes


def encrypt_rsa(plain_bytes, e, n):
    numeric_text = [ord(char) for char in plain_text]
    cipher_text = [pow(num, e, n) for num in numeric_text]
    
    cipher_bytes = b"".join(num.to_bytes((n.bit_length() + 7) // 8, 'big') for num in cipher_text)
    
    return cipher_int

def main():
    key256="12345678abcdefghvbnmfgds12345678"
    key_bytes_256=key256.encode('utf-8')
    AES256_keys = key_expansion.key_expansion(key_bytes_256).key_expansion_256()
    print(AES256_keys,"number of words:",len(AES256_keys))
    print("🔐 AES Key Input Options:")
    print("1. Enter AES key manually (hex format)")
    print("2. Generate random AES key (256-bit)")
    choice = input("Choose (1 or 2): ").strip()

    if choice == "1":
        user_hex = input("Enter AES key in hex (32, 48, or 64 hex digits for 128/192/256-bit): ").strip()
        try:
            aes_key = bytes.fromhex(user_hex)
            if len(aes_key) not in [16, 24, 32]:
                raise ValueError("Invalid AES key length.")
        except ValueError:
            print("❌ Invalid hex or length. Make sure it's 32, 48, or 64 hex characters.")
            return
    else:
        aes_key = secrets.token_bytes(32)  # Default to 256-bit
        print(f"✅ Generated AES Key (hex): {key256}")

    try:
        e = int(input("Enter RSA public exponent e: "))
        n = int(input("Enter RSA modulus n: "))
    except ValueError:
        print("❌ Invalid RSA input. Please enter valid integers.")
        return

    encrypted_base64 = encrypt_rsa(key256, e, n)

    # Define output file path
    output_file = "aes_encryption_using_RSA.txt"

    # Check current working directory
    print(f"📂 Current working directory: {os.getcwd()}")

    # Ensure file exists or create it
    if not os.path.exists(output_file):
        open(output_file, 'w').close()  # Create the file

    # Save to file
    try:
        with open(output_file, "w") as f:
            f.write("AES Key (hex):\n")
            f.write(aes_key.hex() + "\n\n")
            f.write("Encrypted AES Key:\n")
            f.write(encrypted_base64 + "\n")

        print(f"\n✅ Encrypted AES key saved to '{output_file}'")
    except Exception as e:
        print(f"❌ Error saving to file: {e}")

if __name__ == "__main__":
    main()
