from pwn import xor

# Hex strings
KEY1 = bytes.fromhex("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313")
KEY2_raw = bytes.fromhex("37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e")
KEY3_raw = bytes.fromhex("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1")
FLAG_raw = bytes.fromhex("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf")

# Step-by-step decryption
KEY2 = xor(KEY1, KEY2_raw)
KEY3 = xor(KEY2, KEY3_raw)
FLAG = xor(FLAG_raw, KEY1, KEY2, KEY3)

# Print final flag
print(f"crypto{{{FLAG.decode()}}}")
