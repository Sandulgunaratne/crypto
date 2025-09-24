from Crypto.Hash import SHA256  # Import the hashing function
import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import hashlib
import psutil
from time import perf_counter
import os

class SimpleCryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypto")

        # Initialize RSA keys
        self.rsa_key = None
        self.public_key = None
        self.aes_key = None  # We'll generate the AES key automatically

        # Create GUI components
        self.create_widgets()

    def create_widgets(self):
        # Dropdown to select the algorithm (AES, RSA, or Hash)
        tk.Label(self.root, text="Select Algorithm:").pack(pady=5)
        self.algo_var = tk.StringVar(value="AES")
        self.algo_dropdown = tk.OptionMenu(self.root, self.algo_var, "AES", "RSA", "SHA-256", command=self.on_algo_change)
        self.algo_dropdown.pack(pady=5)

        # Dropdown for key size (disabled for Hash)
        tk.Label(self.root, text="Select Key Size:").pack(pady=5)
        self.key_size_var = tk.StringVar(value="128")
        self.key_size_dropdown = tk.OptionMenu(self.root, self.key_size_var, "128", "192", "256")
        self.key_size_dropdown.pack(pady=5)

        # Text area for plaintext input
        self.text_input = tk.Text(self.root, height=5, width=40)
        self.text_input.pack(pady=10)

        # Label and text area for displaying the encrypted message
        tk.Label(self.root, text="Encrypted/Hashed Message:").pack(pady=5)
        self.encrypted_output = tk.Text(self.root, height=5, width=40)
        self.encrypted_output.pack(pady=5)

        # Buttons for encryption, decryption, and hashing
        tk.Button(self.root, text="Encrypt/Hash", command=self.encrypt_message).pack(pady=5)
        tk.Button(self.root, text="Decrypt", command=self.decrypt_message).pack(pady=5)

    def on_algo_change(self, value):
        """Adjust UI based on selected algorithm."""
        if value == "RSA":
            self.key_size_var.set("2048")
            self.key_size_dropdown["menu"].delete(0, "end")
            self.key_size_dropdown["menu"].add_command(label="1024", command=tk._setit(self.key_size_var, "1024"))
            self.key_size_dropdown["menu"].add_command(label="2048", command=tk._setit(self.key_size_var, "2048"))
            self.key_size_dropdown["menu"].add_command(label="4096", command=tk._setit(self.key_size_var, "4096"))
        elif value == "AES":
            self.key_size_var.set("128")
            self.key_size_dropdown["menu"].delete(0, "end")
            self.key_size_dropdown["menu"].add_command(label="128", command=tk._setit(self.key_size_var, "128"))
            self.key_size_dropdown["menu"].add_command(label="192", command=tk._setit(self.key_size_var, "192"))
            self.key_size_dropdown["menu"].add_command(label="256", command=tk._setit(self.key_size_var, "256"))
        elif value == "SHA-256":
            self.key_size_var.set("")
            self.key_size_dropdown["menu"].delete(0, "end")  # Disable key size selection for hashing

    def hash_message(self, plaintext):
        """SHA-256 hashing function."""
        sha256_hash = hashlib.sha256()
        sha256_hash.update(plaintext.encode())
        return sha256_hash.hexdigest()

    def encrypt_message(self):
        plaintext = self.text_input.get("1.0", tk.END).strip()
        algorithm = self.algo_var.get()

        # Measure time, CPU, and memory usage before operation
        start_time = perf_counter()
        start_cpu = self.get_cpu_usage()
        start_memory = self.get_memory_usage()

        if algorithm == "AES":
            key_size = int(self.key_size_var.get())
            try:
                encrypted_message = self.aes_encrypt(key_size, plaintext)
                self.encrypted_output.delete("1.0", tk.END)
                self.encrypted_output.insert(tk.END, encrypted_message)
                messagebox.showinfo("AES Encryption", f"AES Key (auto-generated): {self.aes_key.hex()}")
            except Exception as e:
                messagebox.showerror("Error", f"Error in AES encryption: {e}")
        elif algorithm == "RSA":
            key_size = int(self.key_size_var.get())
            self.generate_rsa_key(key_size)
            try:
                encrypted_message = self.rsa_encrypt(plaintext)
                self.encrypted_output.delete("1.0", tk.END)
                self.encrypted_output.insert(tk.END, encrypted_message)
                messagebox.showinfo("RSA Encryption", f"RSA Key (auto-generated, {key_size}-bit)")
            except Exception as e:
                messagebox.showerror("Error", f"Error in RSA encryption: {e}")
        elif algorithm == "SHA-256":
            try:
                hashed_message = self.hash_message(plaintext)
                self.encrypted_output.delete("1.0", tk.END)
                self.encrypted_output.insert(tk.END, hashed_message)
                messagebox.showinfo("SHA-256 Hash", f"Hashed message: {hashed_message}")
            except Exception as e:
                messagebox.showerror("Error", f"Error in hashing: {e}")

        # Measure time, CPU, and memory usage after operation
        end_time = perf_counter()
        end_cpu = self.get_cpu_usage()
        end_memory = self.get_memory_usage()

        # Calculate time taken, CPU usage difference, and memory usage difference
        time_taken = end_time - start_time
        cpu_usage_diff = end_cpu - start_cpu
        memory_usage_diff = end_memory - start_memory

        messagebox.showinfo("Performance", f"Time Taken: {time_taken:.6f} seconds\n"
                                           f"CPU Usage: {cpu_usage_diff}%\n"
                                           f"Memory Usage Change: {memory_usage_diff:.2f} MB")

    def decrypt_message(self):
        # Implement decryption logic if required
        pass

    def aes_encrypt(self, key_size, plaintext):
        """AES encryption logic"""
        self.aes_key = os.urandom(key_size // 8)  # Auto-generate AES key
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return b64encode(cipher.iv + ciphertext).decode()

    def rsa_encrypt(self, plaintext):
        """RSA encryption logic"""
        cipher = PKCS1_OAEP.new(self.public_key)
        ciphertext = cipher.encrypt(plaintext.encode())
        return b64encode(ciphertext).decode()

    def generate_rsa_key(self, key_size):
        """Generate RSA key pair"""
        self.rsa_key = RSA.generate(key_size)
        self.public_key = self.rsa_key.publickey()

    def get_cpu_usage(self):
        return psutil.cpu_percent()

    def get_memory_usage(self):
        return psutil.virtual_memory().used / (1024 * 1024)  # in MB

# Main execution
if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleCryptoApp(root)
    root.mainloop()
