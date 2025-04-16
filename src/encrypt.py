import os
import shlex
import shutil
from utils.treekem import TreeNode
from utils.crypto import aes_encrypt, encrypt_watermark, encrypt_long_message, encrypt_photo
from utils.watermark import dct_watermark_color, encode_lsb

# Get the project root (src/)
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

def save_derived_key(derived_key, filename):
    with open(os.path.join(PROJECT_ROOT, "output", "encrypted", filename), "wb") as file:
        file.write(derived_key)

def encrypt_and_save_text(root, message, derived_key_filename="derived_key.bin"):
    derived_key = root.group_key
    encrypted_chunks = encrypt_long_message(message, derived_key)
    save_derived_key(derived_key, derived_key_filename)
    with open(os.path.join(PROJECT_ROOT, "output", "encrypted", "encrypted_messages.txt"), "wb") as file:
        for chunk in encrypted_chunks:
            file.write(chunk)
    print("Encrypted Message chunks:")
    for i, chunk in enumerate(encrypted_chunks):
        print(f"Chunk {i + 1}: {chunk}")

def encrypt_and_save_photo(root, photo_path, watermark_options={}, derived_key_filename="derived_key.bin"):
    derived_key = root.group_key
    temp_photo_path = photo_path
    save_derived_key(derived_key, derived_key_filename)

    # Ask user for custom filenames
    dct_output_filename = input("Enter filename for DCT watermarked photo (default: dct_watermarked.png): ").strip() or "dct_watermarked.png"
    lsb_output_filename = input("Enter filename for LSB watermarked photo (default: lsb_watermarked.png): ").strip() or "lsb_watermarked.png"
    final_output_filename = input("Enter filename for final watermarked photo (default: final_watermarked.png): ").strip() or "final_watermarked.png"

    # Apply DCT watermark first if chosen
    if watermark_options.get('dct', False):
        watermark_image = watermark_options.get('dct_watermark_path', os.path.join(PROJECT_ROOT, "data", "watermarks", "watermark.png"))
        dct_output_path = os.path.join(PROJECT_ROOT, "output", "decrypted", dct_output_filename)
        temp_photo_path = dct_watermark_color(temp_photo_path, watermark_image, dct_output_path)
        print(f"DCT watermarked photo saved to {dct_output_path}")

    # Apply LSB watermark on the image with DCT watermark (if both are chosen)
    if watermark_options.get('lsb', False):
        lsb_text = watermark_options.get('lsb_text', "SecretMessage")
        encrypt_lsb_text = aes_encrypt(lsb_text.encode(), derived_key)
        if watermark_options.get('dct', False):
            lsb_input_path = dct_output_path  # Use the DCT watermarked image
        else:
            lsb_input_path = temp_photo_path  # Use the original image
        lsb_output_path = os.path.join(PROJECT_ROOT, "output", "decrypted", lsb_output_filename)
        temp_photo_path = encode_lsb(lsb_input_path, encrypt_lsb_text, lsb_output_path)
        print(f"LSB watermarked photo saved to {lsb_output_path}")
        lsb_length = len(encrypt_lsb_text)
        with open(os.path.join(PROJECT_ROOT, "output", "encrypted", derived_key_filename), "ab") as file:
            file.write(lsb_length.to_bytes(4, byteorder='big'))

    # Save the final watermarked image
    final_output_path = os.path.join(PROJECT_ROOT, "output", "decrypted", final_output_filename)
    shutil.copy(temp_photo_path, final_output_path)
    print(f"Final watermarked photo saved to {final_output_path}")

if __name__ == "__main__":
    os.makedirs(os.path.join(PROJECT_ROOT, "output", "encrypted"), exist_ok=True)
    os.makedirs("temp", exist_ok=True)
    root = TreeNode()
    
    choice = input("What would you like to encrypt? Enter 'text' or 'photo': ").strip().lower()
    num_members = int(input("Number of members in the group: "))

    for _ in range(num_members):
        new_private_key = root.generate_private_key()
        new_public_key = new_private_key.public_key()
        root.add_member_TreeNode(new_public_key)

    root.update_key_TreeNode()

    # Ask for derived key filename
    derived_key_filename = input("Enter filename for the derived key (default: derived_key.bin): ").strip() or "derived_key.bin"

    if choice == 'text':
        message = input("Please enter the text message you want to encrypt: ")
        encrypt_and_save_text(root, message, derived_key_filename)
    elif choice == 'photo':
        photo_path = input("Please enter the path of the photo you want to encrypt (default: data/photos/testphoto.png): ").strip() or os.path.join(PROJECT_ROOT, "data", "photos", "testphoto.png")
        watermark_options = {}
        dct_choice = input("Add DCT watermark? (yes/no): ").strip().lower()
        if dct_choice == 'yes':
            watermark_path = input("Enter watermark image path (default: data/watermarks/watermark.png): ").strip() or os.path.join(PROJECT_ROOT, "data", "watermarks", "watermark.png")
            watermark_options['dct'] = True
            watermark_options['dct_watermark_path'] = watermark_path
        
        lsb_choice = input("Add LSB watermark? (yes/no): ").strip().lower()
        if lsb_choice == 'yes':
            lsb_text = input("Enter LSB watermark text (default: SecretMessage): ").strip() or "SecretMessage"
            watermark_options['lsb'] = True
            watermark_options['lsb_text'] = lsb_text
        
        encrypt_and_save_photo(root, photo_path, watermark_options, derived_key_filename)
    else:
        print("Invalid input. Please enter 'text' or 'photo'.")
        exit()

    root.print_tree()

    action = input("Would you like to add or remove members? (add/remove/no): ")
    if action == "add":
        new_private_key = root.generate_private_key()
        new_public_key = new_private_key.public_key()
        root.add_member_TreeNode(new_public_key)
        print("New member added.")
        root.update_key_TreeNode()
        if choice == 'photo' and watermark_options:
            derived_key_filename = input("Enter filename for the derived key (default: derived_key.bin): ").strip() or "derived_key.bin"
            encrypt_and_save_photo(root, photo_path, watermark_options, derived_key_filename)
        elif choice == 'text':
            derived_key_filename = input("Enter filename for the derived key (default: derived_key.bin): ").strip() or "derived_key.bin"
            encrypt_and_save_text(root, message, derived_key_filename)
        root.print_tree()
    elif action == "remove":
        index_to_remove = int(input("Enter the index of the member to remove (starting from 0): "))
        if 0 <= index_to_remove < len(root.children):
            root.remove_member_TreeNode(root.children[index_to_remove].public_key)
            print("Member removed.")
            root.update_key_TreeNode()
            if choice == 'photo' and watermark_options:
                derived_key_filename = input("Enter filename for the derived key (default: derived_key.bin): ").strip() or "derived_key.bin"
                encrypt_and_save_photo(root, photo_path, watermark_options, derived_key_filename)
            elif choice == 'text':
                derived_key_filename = input("Enter filename for the derived key (default: derived_key.bin): ").strip() or "derived_key.bin"
                encrypt_and_save_text(root, message, derived_key_filename)
            root.print_tree()
        else:
            print("Invalid index.")
    elif action == "no":
        print("No changes were made to the members.")
    else:
        print("Invalid input. Please enter 'add', 'remove', or 'no'.")