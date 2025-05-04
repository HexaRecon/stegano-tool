import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
from cryptography.fernet import Fernet
import base64
import os
import hashlib
import threading
import time

# --- Crypto Functions ---
def generate_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_message(message: str, password: str) -> str:
    key = generate_key(password)
    fernet = Fernet(key)
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message: str, password: str) -> str:
    key = generate_key(password)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message.encode()).decode()

# --- Steganography Functions ---
def text_to_binary(text: str) -> str:
    return ''.join(format(ord(c), '08b') for c in text)

def binary_to_text(binary: str) -> str:
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)

def hide_text_in_image(image_path: str, text: str, output_path: str):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    binary_text = text_to_binary(text) + '1111111111111110'
    data = list(img.getdata())

    if len(binary_text) > len(data) * 3:
        raise ValueError("Image too small to hold the message.")

    new_data = []
    binary_index = 0

    for pixel in data:
        r, g, b = pixel
        if binary_index < len(binary_text):
            r = (r & ~1) | int(binary_text[binary_index])
            binary_index += 1
        if binary_index < len(binary_text):
            g = (g & ~1) | int(binary_text[binary_index])
            binary_index += 1
        if binary_index < len(binary_text):
            b = (b & ~1) | int(binary_text[binary_index])
            binary_index += 1
        new_data.append((r, g, b))

    img.putdata(new_data)
    img.save(output_path)

def extract_text_from_image(image_path: str) -> str:
    img = Image.open(image_path)
    data = list(img.getdata())
    binary_text = ""

    for pixel in data:
        for channel in pixel[:3]:
            binary_text += str(channel & 1)

    end_index = binary_text.find('1111111111111110')
    if end_index != -1:
        binary_text = binary_text[:end_index]
    else:
        raise ValueError("No hidden message found.")

    return binary_to_text(binary_text)

# --- GUI Class ---
class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Snow in sanskrit")
        self.image_path = ""

        # --- Color Palette (Light) ---
        self.bg = "#f5f5f5"
        self.panel = "#ffffff"
        self.text = "#2d3748"
        self.accent = "#2b6cb0"
        self.border = "#dcdcdc"
        self.input_bg = "#ffffff"
        self.font = ("Segoe UI", 10)

        self.root.configure(bg=self.bg)

        self.container = tk.Frame(root, bg=self.panel, bd=1, relief="solid")
        self.container.pack(padx=40, pady=40, fill="both", expand=True)

        self.build_widgets()

    def build_widgets(self):
        title_font = ("Segoe UI", 16, "bold")
        label_font = ("Segoe UI", 11)

        # Title
        tk.Label(self.container, text="Encrypt", font=title_font,
                 fg=self.accent, bg=self.panel).pack(pady=(10, 20))

        # Image Selection
        tk.Button(self.container, text="Choose Image", command=self.choose_image,
                  bg=self.accent, fg="white", font=self.font, bd=0,
                  activebackground="#3c7fd9", padx=10, pady=5).pack(pady=(0, 10))

        self.image_label = tk.Label(self.container, text="No image selected",
                                    fg=self.text, bg=self.panel, font=self.font)
        self.image_label.pack()

        # Message
        tk.Label(self.container, text="Message:", fg=self.text,
                 bg=self.panel, font=label_font).pack(anchor="w", padx=15, pady=(15, 0))
        self.message_entry = tk.Text(self.container, height=5, width=60,
                                     bg=self.input_bg, fg=self.text,
                                     insertbackground=self.text, bd=1, relief="solid", wrap="word")
        self.message_entry.pack(padx=15, pady=(0, 10))

        # Password
        tk.Label(self.container, text="Password:", fg=self.text,
                 bg=self.panel, font=label_font).pack(anchor="w", padx=15)
        password_frame = tk.Frame(self.container, bg=self.panel)
        password_frame.pack(padx=15, pady=(0, 20))

        self.password_entry = tk.Entry(password_frame, show="★",
                                       bg=self.input_bg, fg=self.text, insertbackground=self.text,
                                       bd=1, relief="solid", width=40)
        self.password_entry.pack(side="left")

        self.show_button = tk.Button(password_frame, text="Show", font=("Segoe UI", 8), command=self.show_password_temp)
        self.show_button.pack(side="left", padx=(5, 0))

        # Buttons
        btn_frame = tk.Frame(self.container, bg=self.panel)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Encrypt + Hide", width=20,
                  bg=self.accent, fg="white", font=self.font,
                  bd=0, activebackground="#3c7fd9", padx=10, pady=6,
                  command=self.encrypt_and_hide).pack(side="left", padx=10)

        tk.Button(btn_frame, text="Extract + Decrypt", width=20,
                  bg=self.accent, fg="white", font=self.font,
                  bd=0, activebackground="#3c7fd9", padx=10, pady=6,
                  command=self.extract_and_decrypt).pack(side="left", padx=10)

    def show_password_temp(self):
        def toggle():
            self.password_entry.config(show="")
            time.sleep(0.5)
            self.password_entry.config(show="★")
        threading.Thread(target=toggle).start()

    def choose_image(self):
        file_path = filedialog.askopenfilename(filetypes=[
            ("Image Files", "*.png *.jpg *.jpeg *.bmp *.tiff *.gif"),
            ("All Files", "*.*")
        ])
        if file_path:
            self.image_path = file_path
            self.image_label.config(text=os.path.basename(file_path))

    def encrypt_and_hide(self):
        if not self.image_path:
            messagebox.showerror("Error", "No image selected.")
            return

        message = self.message_entry.get("1.0", tk.END).strip()
        password = self.password_entry.get()

        if not message or not password:
            messagebox.showerror("Error", "Please enter both a message and password.")
            return

        try:
            encrypted = encrypt_message(message, password)
            output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[
                ("PNG", "*.png"), ("BMP", "*.bmp"), ("All Files", "*.*")
            ])
            if not output_path:
                return
            hide_text_in_image(self.image_path, encrypted, output_path)
            messagebox.showinfo("Success", f"Message hidden in image:\n{output_path}")
            # Clear inputs
            self.message_entry.delete("1.0", tk.END)
            self.password_entry.delete(0, tk.END)
            self.image_label.config(text="No image selected")
            self.image_path = ""
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hide message:\n{e}")

    def extract_and_decrypt(self):
        if not self.image_path:
            messagebox.showerror("Error", "No image selected.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter the password.")
            return

        try:
            encrypted = extract_text_from_image(self.image_path)
            decrypted = decrypt_message(encrypted, password)
            self.message_entry.delete("1.0", tk.END)
            self.message_entry.insert(tk.END, decrypted)
            messagebox.showinfo("Success", "Message successfully extracted and decrypted!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract or decrypt message:\n{e}")

# --- Main Execution ---
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("850x600")
    root.minsize(750, 500)
    app = StegoApp(root)
    root.mainloop()
