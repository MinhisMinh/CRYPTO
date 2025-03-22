import math
import string
import sys
import numpy as np
from sympy import Matrix

# Create two dictionaries, English alphabet to numbers and numbers to English alphabet, and returns them
def get_alphabet():
    alphabet = {character: string.ascii_uppercase.index(character) for character in string.ascii_uppercase}
    reverse_alphabet = {value: key for key, value in alphabet.items()}
    return alphabet, reverse_alphabet

# Get input from the user and checks if respects the alphabet
def get_text_input(message, alphabet):
    while True:
        text = input(message)
        text = text.upper().replace(" ", "")
        if all(keys in alphabet for keys in text):
            return text
        else:
            print("\nThe text must contain only characters from the English alphabet ([A to Z] or [a to z]).")

# Check if the key is a square in length
def is_square(key):
    key_length = len(key)
    if 2 <= key_length == int(math.sqrt(key_length)) ** 2:
        return True
    else:
        return False

# Create the matrix k for the key
def get_key_matrix(key, alphabet):
    k = [alphabet[character] for character in key]
    m = int(math.sqrt(len(k)))
    return np.reshape(k, (m, m))

# Create the matrix of m-grams of a text, if needed, complete the last m-gram with the last letter of the alphabet
def get_text_matrix(text, m, alphabet):
    matrix = [alphabet[character] for character in text]
    remainder = len(text) % m
    if remainder != 0:
        matrix.extend([25] * (m - remainder))
    return np.reshape(matrix, (int(len(matrix) / m), m)).transpose()

# Encrypt a Message and returns the ciphertext matrix
def encrypt(key, plaintext, alphabet):
    m = key.shape[0]
    m_grams = plaintext.shape[1]
    ciphertext = np.zeros((m, m_grams)).astype(int)
    for i in range(m_grams):
        ciphertext[:, i] = np.reshape(np.dot(key, plaintext[:, i]) % len(alphabet), m)
    return ciphertext

# Transform a matrix to a text, according to the alphabet
def matrix_to_text(matrix, order, alphabet):
    text_array = np.ravel(matrix, order='F' if order == 't' else 'C')
    return ''.join(alphabet[val] for val in text_array)

# Check if the key is invertible and in that case returns the inverse of the matrix
def get_inverse(matrix, alphabet):
    alphabet_len = len(alphabet)
    if math.gcd(int(round(np.linalg.det(matrix))), alphabet_len) == 1:
        matrix = Matrix(matrix)
        return np.matrix(matrix.inv_mod(alphabet_len))
    else:
        return None

# Generate a random key matrix of given size and ensure it is invertible
def generate_random_key(matrix_size, alphabet):
    alphabet_len = len(alphabet)
    while True:
        key_matrix = np.random.randint(0, alphabet_len, (matrix_size, matrix_size))
        det = int(np.round(np.linalg.det(key_matrix)))
        if det % alphabet_len != 0 and math.gcd(det, alphabet_len) == 1:
            try:
                Matrix(key_matrix).inv_mod(alphabet_len)
                return key_matrix.tolist()
            except ValueError:
                continue

# Decrypt a Message and returns the plaintext matrix
def decrypt(k_inverse, c, alphabet):
    return encrypt(k_inverse, c, alphabet)

def main():
    # Get two dictionaries, English alphabet to numbers and numbers to English alphabet
    alphabet, reverse_alphabet = get_alphabet()

    # Ask the user for the plaintext and the key, and check the input
    plaintext = get_text_input("\nInsert the text to be encrypted: ", alphabet)
    key = get_text_input("Insert the key for encryption: ", alphabet)

    if is_square(key):
        # Get the key matrix k
        k = get_key_matrix(key, alphabet)
        print("\nKey Matrix:\n", k)

        # Check if the key is invertible, and generate a new one if not
        k_inverse = get_inverse(k, alphabet)
        while k_inverse is None:
            print("\nThe matrix of the key provided is not invertible. Generating a new key...\n")
            k = generate_random_key(int(math.sqrt(len(key))), alphabet)
            k_inverse = get_inverse(k, alphabet)
        print("Key Matrix:\n", k)

        # Get the m-grams matrix p of the plaintext
        p = get_text_matrix(plaintext, k.shape[0], alphabet)
        print("Plaintext Matrix:\n", p)

        # Encrypt the plaintext
        c = encrypt(k, p, alphabet)
        # Transform the ciphertext matrix to a text of the alphabet
        ciphertext = matrix_to_text(c, "t", reverse_alphabet)
        print("\nThe message has been encrypted.\n")
        print("Generated Ciphertext: ", ciphertext)
        print("Generated Ciphertext Matrix:\n", c, "\n")

        # Decrypt the ciphertext
        if k_inverse is not None:
            p_decrypted = decrypt(k_inverse, c, alphabet)
            # Transform the decrypted matrix back to a text
            plaintext_decrypted = matrix_to_text(p_decrypted, "t", reverse_alphabet)
            print("\nThe message has been decrypted.\n")
            print("Generated Plaintext: ", plaintext_decrypted)
            print("Generated Plaintext Matrix:\n", p_decrypted, "\n")
        else:
            print("\nThe matrix of the key provided is not invertible.\n")
    else:
        print("\nThe length of the key must be a square and >= 2.\n")

if __name__ == '__main__':
    main()
