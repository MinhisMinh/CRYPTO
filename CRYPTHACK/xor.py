from pwn import xor

label = b"label"  # Note: must be bytes
result = xor(label, 13)     # XOR with integer
flag = f"crypto{{{result.decode('utf-8')}}}"
print(flag)
