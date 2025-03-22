import string

def mod_inverse(a, m):
    """
    Computes the modular inverse of a modulo
    m using a simple brute-force approach.
    Returns the inverse if it exists, else None.
    """
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None
def affine_decrypt(text, a, b):
    """
    Decrypts the input text using the Affine cipher with keys a and b.
    Computes the modular inverse of a and applies the decryption formula:
      D(y) = a_inv * (y - b) mod 26.
    """
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return
    
    alphabets = string.ascii_uppercase
    result = []
    for char in text:
        if char.isupper():
            y = ord(char) - ord('A')
            x = (a_inv * (y - b)) % 26
            result.append(alphabets[x])
        elif char.islower():
            y = ord(char.upper()) - ord('A')
            x = (a_inv * (y - b)) % 26
            result.append(alphabets[x].lower())
        else:
            result.append(char)
    return ''.join(result)

def main():
    encrypted_text = input("\nEnter the encrypted text to decrypt: ")
    for a in range (2,26):
        if mod_inverse(a,26) != None:
            for b in range (25):
                decrypted_text = affine_decrypt(encrypted_text, a, b)
                print("\nDecrypted text:")
                print(decrypted_text)
                #The code under here to see each loop
                # input("\nPress Enter to continue to decryption...")

if __name__ == "__main__":
    main()

##Some input
#text = "Pe acgrwenj; eleracxe enwe yw knrekza bkiex." (a = 5, b = 10)
#text = "H'x vrgihvq, hxwbmhrom boa b ghmmgr hovrjder. H xbpr xhvmbprv, H bx fdm fi jfomefg boa bm mhxrv qbea mf qboagr. Sdm hi tfd jbo'm qboagr xr bm xt lfevm, mqro tfd vder bv qrgg afo'm arvreur xr bm xt srvm." (a = 17, b = 1)