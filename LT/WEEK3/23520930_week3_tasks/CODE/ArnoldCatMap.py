from PIL import Image
import numpy as np

# Arnold Cat Map function
def ArnoldCatTransform(img):
    rows, cols, ch = img.shape
    n = rows
    img_arnold = np.zeros_like(img)
    for x in range(n):
        for y in range(n):
            new_x = (x + y) % n
            new_y = (x + 2 * y) % n
            img_arnold[new_x, new_y] = img[x, y]
    return img_arnold

# Inverse Arnold Cat Map function
def ArnoldCatInverseTransform(img):
    rows, cols, ch = img.shape
    n = rows
    img_inverse = np.zeros_like(img)
    for x in range(n):
        for y in range(n):
            new_x = (2 * x - y) % n
            new_y = (-x + y) % n
            img_inverse[x, y] = img[new_x, new_y]
    return img_inverse

# Finding the period of Arnold's cat map
def find_period(img_size):
    img = np.arange(img_size * img_size).reshape((img_size, img_size, 1))
    original = img.copy()
    count = 0
    while True:
        img = ArnoldCatTransform(img)
        count += 1
        if np.array_equal(img, original):
            return count  # The cycle repeats after 'count' iterations

# Encryption function
def ArnoldCatEncryption(imageName, key):
    img = np.array(Image.open(imageName).convert("RGB"))  # Convert image to RGB
    for _ in range(key):
        img = ArnoldCatTransform(img)
    Image.fromarray(img.astype('uint8')).save(imageName.split('.')[0] + "_ArnoldcatEnc.png")
    return img

# Decryption function
def ArnoldCatDecryption(imageName, key):
    img = np.array(Image.open(imageName).convert("RGB"))  # Convert image to RGB
    period = find_period(img.shape[0])  # Find Arnold Map Period
    key = key % period  # Adjust key to be within the correct period

    for _ in range(key):
        img = ArnoldCatInverseTransform(img)

    Image.fromarray(img.astype('uint8')).save(imageName.split('_')[0] + "_ArnoldcatDec.png")
    return img

# Main function
def main():
    print("=== Arnold Cat Using Image ===")
    print("*This program will encrypt/decrypt an image (must be square image) using Arnold Cat Map.")
    mode = input("Enter mode (encrypt/decrypt): ").strip().lower()
    if mode not in ("encrypt", "decrypt"):
        print("Invalid mode. Use 'encrypt' or 'decrypt'.")
        return
    
    image_file = input("Enter path to image file: ").strip()
    key = int(input("Enter the key (integer number): ").strip())

    if mode == "encrypt":
        ArnoldCatEncryption(image_file, key)
        print(f"\nDone. Encrypted file saved as '{image_file.split('.')[0]}_ArnoldcatEnc.png'.")
    elif mode == "decrypt":
        ArnoldCatDecryption(image_file, key)
        print(f"\nDone. Decrypted file saved as '{image_file.split('_')[0]}_ArnoldcatDec.png'.")

if __name__ == "__main__":
    main()
