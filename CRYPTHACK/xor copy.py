from pwn import xor

hex_data = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"
data = bytes.fromhex(hex_data)

# Known part of the flag and partial key
known = b'crypto{'

# XOR first part to verify the key pattern
partial_key = xor(data[:], known)
print(f"Partial key found: {partial_key.decode()}")  # Should show 'myXORke'

xor(data, partial_key)  # XOR the entire data with the found key
print(f"Decrypted data: {xor(data, partial_key).decode()}")  # Should show the decrypted flag
# The above code is a more efficient way to find the key and decrypt the data.
