from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os

class TreeNode:
    def __init__(self):
        self.children = []
        self.group_key = None

    def generate_private_key(self):
        return x25519.X25519PrivateKey.generate()

    def add_member_TreeNode(self, new_public_key):
        new_node = TreeNode()
        new_node.public_key = new_public_key
        self.children.append(new_node)
        self.update_key_TreeNode()

    def remove_member_TreeNode(self, public_key_to_remove):
        for child in self.children:
            if child.public_key == public_key_to_remove:
                self.children.remove(child)
                self.update_key_TreeNode()
                break

    def update_key_TreeNode(self):
        self.group_key = self.generate_group_key_TreeNode()

    def generate_group_key_TreeNode(self):
        if not self.children:
            return os.urandom(32)
        combined_key = b''.join(child.generate_group_key_TreeNode() for child in self.children)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            info=b'',
        ).derive(combined_key)

    def print_tree(self, level=0):
        if not self.children:
            print("  " * level + f"Leaf Node Level {level}: Public Key: {self.public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()}")
        else:
            print("  " * level + f"Node Level {level}: Group Key: {self.group_key.hex()}")
        for child in self.children:
            child.print_tree(level + 1)