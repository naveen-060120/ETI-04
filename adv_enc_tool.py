import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets


# -------- AES Helper Functions -------- #
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(file_path, password):
    """Encrypt file with AES-256 and save as .enc."""
    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Generate salt & IV
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(16)

    # Pad plaintext
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Save as Base64 (salt + iv + ciphertext)
    enc_data = base64.b64encode(salt + iv + ciphertext)

    with open(file_path + ".enc", "wb") as f:
        f.write(enc_data)


def decrypt_file(file_path, password):
    """Decrypt file with AES-256."""
    with open(file_path, "rb") as f:
        enc_data = f.read()

    try:
        enc_data = base64.b64decode(enc_data)
    except Exception:
        raise ValueError("File is not a valid encrypted file.")

    if len(enc_data) < 32:
        raise ValueError("Encrypted file is too short or corrupted.")

    # Extract salt, IV, ciphertext
    salt, iv, ciphertext = enc_data[:16], enc_data[16:32], enc_data[32:]
    key = derive_key(password, salt)

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    try:
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    except Exception:
        raise ValueError("Incorrect password or corrupted file.")

    out_file = file_path.replace(".enc", "_decrypted")
    with open(out_file, "wb") as f:
        f.write(plaintext)


# -------- GUI -------- #
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256 Encryption Tool")
        self.root.geometry("400x250")

        tk.Label(root, text="Advanced Encryption Tool (AES-256)", font=("Arial", 12, "bold")).pack(pady=10)

        self.password_label = tk.Label(root, text="Enter Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack(pady=5)

        self.encrypt_button = tk.Button(root, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(root, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack(pady=5)

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password required")
            return
        try:
            encrypt_file(file_path, password)
            messagebox.showinfo("Success", "File encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password required")
            return
        try:
            decrypt_file(file_path, password)
            messagebox.showinfo("Success", "File decrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")


# -------- Run App -------- #
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
