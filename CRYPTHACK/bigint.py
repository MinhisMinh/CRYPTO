from Crypto.Util.number import *

encrypted_num = 11515195063862318899931685488813747395775516287289682636499965282714637259206269

byte_length = (encrypted_num.bit_length()+7) // 8
decrypted_byte = encrypted_num.to_bytes(byte_length,byteorder="big")

plaintext = decrypted_byte.decode("utf-8")

print(plaintext)