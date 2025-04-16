import os
from utils.crypto import aes_decrypt, decrypt_message, decrypt_watermark
from utils.watermark import extract_dct_watermark, decode_lsb

# Get the project root (src/)
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

def load_derived_key(filename):
    with open(os.path.join(PROJECT_ROOT, "output", "encrypted", filename), "rb") as file:
        derived_key = file.read(32)  # First 32 bytes are the derived key
        lsb_length_bytes = file.read(4)  # Next 4 bytes are the LSB watermark length
        lsb_length = int.from_bytes(lsb_length_bytes, byteorder='big') if lsb_length_bytes else None
        return derived_key, lsb_length

def decrypt_and_save_text(derived_key_filename="derived_key.bin"):
    derived_key, _ = load_derived_key(derived_key_filename)
    with open(os.path.join(PROJECT_ROOT, "output", "encrypted", "encrypted_messages.txt"), "rb") as file:
        encrypted_data = file.read()
    decrypted_message = decrypt_message(encrypted_data, derived_key)
    print("Decrypted message:", decrypted_message)

def decrypt_dct_watermark(original_image_path, watermarked_image_path, output_watermark_path):
    """
    Extract and save the DCT watermark from a watermarked image.
    """
    try:
        extracted_path = extract_dct_watermark(original_image_path, watermarked_image_path, output_watermark_path)
        if extracted_path:
            print(f"DCT watermark extracted and saved to {extracted_path}")
        else:
            print("Failed to extract DCT watermark.")
    except Exception as e:
        print(f"Error extracting DCT watermark: {e}")

def decrypt_lsb_watermark(watermarked_image_path, lsb_length, derived_key):
    """
    Extract and decrypt the LSB watermark from a watermarked image.
    """
    try:
        lsb_watermark_bytes = decode_lsb(watermarked_image_path, lsb_length)
        if lsb_watermark_bytes:
            decrypted_lsb_watermark = decrypt_watermark(lsb_watermark_bytes, derived_key)
            print(f"Extracted LSB watermark: {decrypted_lsb_watermark.decode('utf-8', errors='ignore')}")
        else:
            print("No LSB watermark found.")
    except ValueError as e:
        print(f"Failed to decrypt LSB watermark: {e}")

if __name__ == "__main__":
    os.makedirs(os.path.join(PROJECT_ROOT, "output", "decrypted"), exist_ok=True)
    os.makedirs(os.path.join(PROJECT_ROOT, "output", "extracted"), exist_ok=True)
    choice = input("What would you like to decrypt? Enter 'text' or 'photo': ").strip().lower()

    # Ask for derived key filename
    derived_key_filename = input("Enter filename of the derived key (default: derived_key.bin): ").strip() or "derived_key.bin"
    derived_key, lsb_length = load_derived_key(derived_key_filename)
    
    if choice == 'text':
        decrypt_and_save_text(derived_key_filename)
    elif choice == 'photo':
        # Ask user for the photo to decrypt
        photo_to_decrypt = input("Enter the filename of the photo to decrypt (default: final_watermarked.png): ").strip() or "final_watermarked.png"
        dct_watermarked_image_path = os.path.join(PROJECT_ROOT, "output", "decrypted", photo_to_decrypt)
        lsb_watermarked_image_path = os.path.join(PROJECT_ROOT, "output", "decrypted", photo_to_decrypt)
        output_dct_watermark_path = os.path.join(PROJECT_ROOT, "output", "extracted", "extracted_dct_watermark.png")

        # Ask user for the original photo path for DCT watermark extraction
        original_photo_path = input("Please enter the path to the original unwatermarked photo (default: data/photos/testphoto.png): ").strip() or os.path.join(PROJECT_ROOT, "data", "photos", "testphoto.png")
        if not os.path.exists(original_photo_path):
            print(f"Original photo '{original_photo_path}' not found. DCT watermark extraction may fail without it.")
        
        # Decrypt DCT watermark
        if os.path.exists(dct_watermarked_image_path):
            print(f"Decrypting DCT watermark from '{dct_watermarked_image_path}'...")
            decrypt_dct_watermark(original_photo_path, dct_watermarked_image_path, output_dct_watermark_path)
        else:
            print(f"DCT watermarked file '{dct_watermarked_image_path}' not found.")

        # Decrypt LSB watermark
        if os.path.exists(lsb_watermarked_image_path):
            print(f"Decrypting LSB watermark from '{lsb_watermarked_image_path}'...")
            decrypt_lsb_watermark(lsb_watermarked_image_path, lsb_length, derived_key)
        else:
            print(f"LSB watermarked file '{lsb_watermarked_image_path}' not found.")
    else:
        print("Invalid input. Please enter 'text' or 'photo'.")