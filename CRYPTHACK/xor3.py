from pwn import xor

hex_data = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"
print(len(hex_data))
data = bytes.fromhex(hex_data)
print(len(data))
flag = 0
for key in range(256):
    decrypted = xor(data, key)
    try:
        result = decrypted.decode('utf-8')
        if result.startswith("crypto{"):
            print(f"Key: {key}")
            print(f"Flag: {result}")
            flag = 1
            break
    except UnicodeDecodeError:
        continue

if flag == 0:
    print("No flag found")