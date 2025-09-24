import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import psutil
from time import perf_counter
import os

# --- THEME COLORS ---
BG_BLACK = "#000000"
NATURAL_LIGHT_GREEN = "#A8D5BA"  # soft, natural light green
FG_TEXT = NATURAL_LIGHT_GREEN

# Transparent 16x16 icon (Base64)
_BLANK_ICON_B64 = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAEklEQVR4nGNgGAWjYBSMAggAAAQQAAFVN1rQAAAAAElFTkSuQmCC"


class SimpleCryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secret Bunker")  # Window title only
        self.root.configure(bg=BG_BLACK)

        # Replace feather icon with transparent icon
        self._icon_img = None
        self._set_blank_icon()

        # Keys
        self.rsa_key = None
        self.public_key = None
        self.aes_key = None

        # Keep references to images
        self._banner_img = None

        self.create_widgets()

    # ----------------- UI ELEMENTS ----------------- #
    def create_widgets(self):
        # Dropdown for algorithm selection
        self._label("Select Algorithm:").pack(pady=5)
        self.algo_var = tk.StringVar(value="AES")
        self.algo_dropdown = tk.OptionMenu(self.root, self.algo_var, "AES", "RSA", command=self.on_algo_change)
        self._style_menu(self.algo_dropdown)
        self.algo_dropdown.pack(pady=5)

        # Dropdown for key size
        self._label("Select Key Size:").pack(pady=5)
        self.key_size_var = tk.StringVar(value="128")
        self.key_size_dropdown = tk.OptionMenu(self.root, self.key_size_var, "128", "192", "256")
        self._style_menu(self.key_size_dropdown)
        self.key_size_dropdown.pack(pady=5)

        # Plaintext input area
        self.text_input = tk.Text(self.root, height=5, width=40, bg=BG_BLACK, fg=FG_TEXT, insertbackground=FG_TEXT)
        self.text_input.pack(pady=10)
#hello
        # Encrypted message display
        self._label("Encrypted Message:").pack(pady=5)
        self.encrypted_output = tk.Text(self.root, height=5, width=40, bg=BG_BLACK, fg=FG_TEXT, insertbackground=FG_TEXT)
        self.encrypted_output.pack(pady=5)

        # Text encryption/decryption buttons
        self._button("Encrypt Text", self.encrypt_message).pack(pady=5)
        self._button("Decrypt Text", self.decrypt_message).pack(pady=5)

        # File encryption/decryption buttons (AES-GCM)
        self._button("Encrypt File… (AES-GCM)", self.encrypt_file_dialog).pack(pady=5)
        self._button("Decrypt File… (AES-GCM)", self.decrypt_file_dialog).pack(pady=5)

    # ----------------- STYLING HELPERS ----------------- #
    def _label(self, text):
        return tk.Label(self.root, text=text, bg=BG_BLACK, fg=FG_TEXT)

    def _button(self, text, cmd):
        return tk.Button(
            self.root,
            text=text,
            command=cmd,
            bg=NATURAL_LIGHT_GREEN,
            fg="black",
            activebackground=NATURAL_LIGHT_GREEN,
            activeforeground="black",
            relief="flat",
            padx=10,
            pady=6
        )

    def _style_menu(self, widget):
        widget.config(bg=NATURAL_LIGHT_GREEN, fg="black",
                      activebackground=NATURAL_LIGHT_GREEN, activeforeground="black",
                      relief="flat", highlightthickness=0, borderwidth=0)
        menu = widget["menu"]
        menu.config(bg=NATURAL_LIGHT_GREEN, fg="black",
                    activebackground=NATURAL_LIGHT_GREEN, activeforeground="black")

    # ----------------- ICON ----------------- #
    def _set_blank_icon(self):
        """Replace default feather icon with a transparent one."""
        try:
            self._icon_img = tk.PhotoImage(data=_BLANK_ICON_B64)
            self.root.iconphoto(True, self._icon_img)
        except Exception:
            try:
                self.root.iconbitmap("")  # Windows fallback
            except:
                pass

    # ----------------- METRICS ----------------- #
    def get_cpu_usage(self):
        return psutil.cpu_percent(interval=None)

    def get_memory_usage(self):
        process = psutil.Process()
        return process.memory_info().rss / (1024 * 1024)

    # ----------------- CRYPTO FUNCTIONS ----------------- #
    def generate_rsa_key(self, size):
        self.rsa_key = RSA.generate(size)
        self.public_key = self.rsa_key.publickey()

    def generate_aes_key(self, key_size):
        return os.urandom(key_size // 8)

    # AES CBC for text (original)
    def aes_encrypt(self, key_size, plaintext):
        self.aes_key = self.generate_aes_key(key_size)
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return b64encode(cipher.iv + ciphertext).decode()

    def aes_decrypt(self, key_size, ciphertext):
        data = b64decode(ciphertext)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, data[:16])
        return unpad(cipher.decrypt(data[16:]), AES.block_size).decode()

    # RSA
    def rsa_encrypt(self, plaintext):
        cipher = PKCS1_OAEP.new(self.public_key)
        return b64encode(cipher.encrypt(plaintext.encode())).decode()

    def rsa_decrypt(self, ciphertext):
        cipher = PKCS1_OAEP.new(self.rsa_key)
        return cipher.decrypt(b64decode(ciphertext)).decode()

    # AES-GCM for file-level encryption
    def aes_gcm_encrypt_file(self, src_path: str, dst_path: str, key: bytes, aad: bytes = b""):
        """
        File format: [12-byte nonce][16-byte tag][ciphertext...]
        """
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
            fout.write(nonce)
            fout.write(b"\x00" * 16)  # reserve space for tag
            while True:
                chunk = fin.read(1024 * 1024)
                if not chunk:
                    break
                fout.write(cipher.encrypt(chunk))
            tag = cipher.digest()
            fout.seek(12)
            fout.write(tag)

    def aes_gcm_decrypt_file(self, src_path: str, dst_path: str, key: bytes, aad: bytes = b""):
        """
        Reads format: [nonce(12)][tag(16)][ciphertext...]
        """
        with open(src_path, "rb") as fin:
            nonce = fin.read(12)
            tag = fin.read(16)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            if aad:
                cipher.update(aad)
            with open(dst_path, "wb") as fout:
                while True:
                    chunk = fin.read(1024 * 1024)
                    if not chunk:
                        break
                    fout.write(cipher.decrypt(chunk))
                cipher.verify(tag)  # raises ValueError if wrong key or tampered data

    # ----------------- ACTIONS ----------------- #
    def on_algo_change(self, value):
        if value == "RSA":
            self.key_size_var.set("2048")
            self.key_size_dropdown["menu"].delete(0, "end")
            for ks in ("1024", "2048", "4096"):
                self.key_size_dropdown["menu"].add_command(label=ks, command=tk._setit(self.key_size_var, ks))
        else:
            self.key_size_var.set("128")
            self.key_size_dropdown["menu"].delete(0, "end")
            for ks in ("128", "192", "256"):
                self.key_size_dropdown["menu"].add_command(label=ks, command=tk._setit(self.key_size_var, ks))

    # Text encryption/decryption
    def encrypt_message(self):
        plaintext = self.text_input.get("1.0", tk.END).strip()
        algorithm = self.algo_var.get()
        key_size = int(self.key_size_var.get())

        start_time = perf_counter()
        start_cpu = self.get_cpu_usage()
        start_mem = self.get_memory_usage()

        try:
            if algorithm == "AES":
                encrypted = self.aes_encrypt(key_size, plaintext)
                messagebox.showinfo("AES Encryption", f"AES Key (auto-generated): {self.aes_key.hex()}")
            else:
                self.generate_rsa_key(key_size)
                encrypted = self.rsa_encrypt(plaintext)
                messagebox.showinfo("RSA Encryption", f"RSA Key (auto-generated, {key_size}-bit)")

            self.encrypted_output.delete("1.0", tk.END)
            self.encrypted_output.insert(tk.END, encrypted)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

        end_time = perf_counter()
        end_cpu = self.get_cpu_usage()
        end_mem = self.get_memory_usage()
        messagebox.showinfo("Performance",
                            f"Time Taken: {end_time - start_time:.6f} s\n"
                            f"CPU Usage: {end_cpu - start_cpu}%\n"
                            f"Memory Usage Change: {end_mem - start_mem:.2f} MB")

    def decrypt_message(self):
        ciphertext = self.encrypted_output.get("1.0", tk.END).strip()
        algorithm = self.algo_var.get()
        key_size = int(self.key_size_var.get())

        start_time = perf_counter()
        start_cpu = self.get_cpu_usage()
        start_mem = self.get_memory_usage()

        try:
            if algorithm == "AES":
                decrypted = self.aes_decrypt(key_size, ciphertext)
            else:
                decrypted = self.rsa_decrypt(ciphertext)
            messagebox.showinfo("Decrypted Message", decrypted)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

        end_time = perf_counter()
        end_cpu = self.get_cpu_usage()
        end_mem = self.get_memory_usage()
        messagebox.showinfo("Performance",
                            f"Time Taken: {end_time - start_time:.6f} s\n"
                            f"CPU Usage: {end_cpu - start_cpu}%\n"
                            f"Memory Usage Change: {end_mem - start_mem:.2f} MB")

    # ----------------- FILE ACTIONS ----------------- #
    def encrypt_file_dialog(self):
        in_path = filedialog.askopenfilename(title="Select a file to encrypt")
        if not in_path:
            return

        keybits = int(self.key_size_var.get()) if self.algo_var.get() == "AES" else 128
        key = get_random_bytes(keybits // 8)
        out_path = in_path + ".gcm"
        aad = os.path.basename(in_path).encode()

        try:
            t0 = perf_counter()
            self.aes_gcm_encrypt_file(in_path, out_path, key, aad=aad)
            dt = perf_counter() - t0
            messagebox.showinfo(
                "AES-GCM File Encryption",
                f"Encrypted:\n{in_path}\n→ {out_path}\n\nAES-{keybits} key (SAVE THIS SAFELY):\n{key.hex()}\n\nTime: {dt:.4f}s"
            )
        except Exception as e:
            messagebox.showerror("Error", f"File encryption failed:\n{e}")

    def decrypt_file_dialog(self):
        in_path = filedialog.askopenfilename(title="Select a .gcm file to decrypt", filetypes=[("GCM files", "*.gcm"), ("All files", "*.*")])
        if not in_path:
            return

        key_hex = simpledialog.askstring("AES Key", "Paste AES key (hex) used for encryption:")
        if not key_hex:
            return

        try:
            key = bytes.fromhex(key_hex.strip())
        except Exception:
            messagebox.showerror("Error", "Invalid hex key.")
            return

        # Generate output filename
        base = in_path[:-4] if in_path.lower().endswith(".gcm") else in_path
        root_name, ext = os.path.splitext(base)
        out_path = f"{root_name}.dec{ext}" if ext else f"{base}.dec"

        aad = os.path.basename(base).encode()
        try:
            t0 = perf_counter()
            self.aes_gcm_decrypt_file(in_path, out_path, key, aad=aad)
            dt = perf_counter() - t0
            messagebox.showinfo(
                "AES-GCM File Decryption",
                f"Decrypted:\n{in_path}\n→ {out_path}\n\nTime: {dt:.4f}s"
            )
        except ValueError:
            messagebox.showerror("Error", "Decryption failed: wrong key or file was tampered with (MAC check failed).")
        except Exception as e:
            messagebox.showerror("Error", f"File decryption failed:\n{e}")


# ----------------- RUN APP ----------------- #
if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleCryptoApp(root)
    root.mainloop()
