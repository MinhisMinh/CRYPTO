from collections import Counter
import string

# Known English letter frequencies (from most frequent to least frequent)
english_frequencies = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'

cipher_text = (
    "Amgewlu gpu cmhuzft pabu, W pufzl f raj efj gpfg epu pfl cfttuh acc gpu rfov ac puz rajczwuhl’e bagazojotu. Rzavuh puz huov. Epu huxuz vhus spfg pwg puz, pu efwl. W sfe 13. Gpu lufl iwzt pfl ruuh f qmhwaz wh pwip eopaat.Gpu twhu ga euu puz ehfvul fzamhl gpu rmwtlwhi. Raje swgp tahi pfwz, sufzwhi gwue gpuj’l razzasul czab gpuwz cfgpuze, fhl iwzte swgp gpwov rtmu ujuepflas ebavul owifzuggue wh gpu nfzvwhi tag. Eabuahu nfeeul f raggtu ac Qfov. Gpuzu suzu ha flmtge gpuzu, qmeg xuzj atl vwle.Epu ftbaeg taavul twvu epu sfe etuunwhi, ukoung gpfg epu sfe gaa egwtt. Gpuzu sfe f nmccwhuee ga puz cfou gpfg lwlh’g euub ymwgu zwipg. Gpuj pfl lzueeul puz caz gpu nzab; gpu ozwhatwhu etuuxue ac puz iash twvu naace ac nwhv oaggah ofhlj. Eabu vwle nzfjul, rmg W oamtlh’g. W qmeg egfzul fg gpu zaeue wh puz oazefiu."
)


def convert_to_uppercase(text):
    """
    Converts all alphabetic characters in the text to uppercase.
    Non-alphabet characters are preserved.
    """
    return ''.join([char.upper() if char.isalpha() else char for char in text])


# Convert the cipher text to uppercase
cipher_text_upper = convert_to_uppercase(cipher_text)

# Count letter frequencies in the ciphertext (ignoring non-alphabet characters)
cipher_counts = Counter(''.join(filter(str.isalpha, cipher_text_upper)))

# Sort the ciphertext letters by frequency (most frequent first)
sorted_cipher = ''.join([item[0] for item in cipher_counts.most_common()])

# Create a mapping from ciphertext letters to English frequencies
mapping = {}
for i, letter in enumerate(sorted_cipher):
    if i < len(english_frequencies):
        mapping[letter] = english_frequencies[i]

# For any letters not present in the ciphertext, add an identity mapping
for letter in string.ascii_uppercase:
    if letter not in mapping:
        mapping[letter] = letter

# Optional manual adjustments to improve decryption quality
mapping["W"] = "I"
mapping["F"] = "A"
mapping["S"] = "W" ## FAI --> WAS
mapping["E"] = "S" ## FAI --> WAS
mapping["P"] = "H" ## AE --> HE
mapping["P"] = "H" ## SAE --> SHE
mapping["N"] = "P" ## SLEEVIRG --> SLEEPING
mapping["H"] = "N" ## SLEEVIRG --> SLEEPING
mapping["Z"] = "R" ## THENE --> THERE
mapping["B"] = "M" ## SEEB --> SEEM
mapping["M"] = "U" ## QWITE --> QUITE
mapping["J"] = "Y" ## THEP --> THEY
mapping["X"] = "V" ## NEJER --> NEVER
mapping["V"] = "K" ## MNEW --> KNEW
mapping["S"] = "W" ## KHAT --> WHAT
mapping["R"] = "B" ## YOY --> BOY
mapping["Q"] = "J" ## KUNIOR --> JUNIOR
mapping["C"] = "F" ## CROM --> FROM
mapping["O"] = "C" ## MOTORUYULE --> MOTORCYCLE

def print_key_mapping_table(mapping):
    """
    Displays the key mapping in the requested table format:

     A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z
     --+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--
     R  A  T  X  U  K  E  Y  I  O  H  D  V  F  G  M  P  L  A  W  S  Q  J  C  B  N
    """
    plain_letters = list(string.ascii_uppercase)
    # Build the first row: plain letters with a fixed width (2 characters per letter)
    row1 = " ".join(f"{letter:2}" for letter in plain_letters)
    # Build the border row: "--+--+...+--"
    row2 = " " + "--" + "+--" * (len(plain_letters) - 1) + " "
    # Build the third row: corresponding cipher letters from the mapping
    row3 = " ".join(f"{mapping[letter]:2}" for letter in plain_letters)

    print(row1)
    print(row2)
    print(row3)


# Display the final mapping using the desired table format
print_key_mapping_table(mapping)

# Decrypt the ciphertext using the mapping (preserving letter case)
decrypted_text = []
for char in cipher_text_upper:
    if char.isalpha():
        decrypted_text.append(mapping.get(char, char))
    else:
        decrypted_text.append(char)
decrypted_text = ''.join(decrypted_text)
print("\nEncrypted Text:")
print(cipher_text)
print("\nDecrypted Text:")
print(decrypted_text)
