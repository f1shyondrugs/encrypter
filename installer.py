import tkinter as tk
from tkinter import filedialog, messagebox
import os
import threading
import sys
try:
    import requests
    import subprocess
except ModuleNotFoundError:
    print("Setting up...")
    os.system("python -m pip install requests")
    os.system("python -m pip install subprocess")
    import requests
    import subprocess
    

class InstallerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Program Installer")
        self.geometry("400x250")

        # Installation path
        self.install_path_label = tk.Label(self, text="Installation Path:")
        self.install_path_label.pack(pady=5)
        self.install_path_entry = tk.Entry(self, width=40)
        self.install_path_entry.pack(pady=5)
        self.browse_button = tk.Button(self, text="Browse...", command=self.browse_directory)
        self.browse_button.pack(pady=5)

        # Download button
        self.download_button = tk.Button(self, text="Next >", command=self.start_installation)
        self.download_button.config(fg="blue")
        self.download_button.place(relx=0.9, rely=0.9, anchor="se")

        # Progress display
        self.progress_label = tk.Label(self, text="")
        self.progress_label.pack(pady=5)

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.install_path_entry.delete(0, tk.END)
            self.install_path_entry.insert(0, directory)

    def start_installation(self):
        thread = threading.Thread(target=self.install)
        thread.start()

    def install(self):

        self.download_button.config(state="disabled")
        self.browse_button.config(state="disabled")
        self.install_path_entry.config(state="disabled")

        install_path = self.install_path_entry.get()
        if not install_path:
            messagebox.showerror("Error", "Please select an installation path.")
            return

        files_to_download = {
            "ManualWrite": ["FishyCrypter.py", """\nimport os\nimport tkinter as tk\nfrom tkinter import filedialog, messagebox, Menu, Toplevel, Text, Label, simpledialog\nfrom tkinterdnd2 import TkinterDnD, DND_FILES\nfrom cryptography.fernet import Fernet\nimport hashlib\nimport base64\nfrom PIL import Image, ImageTk\n\nKEY_DIR = "data/"\nFILE_DIR = "data/files/"\nPASSWORD_FILE = os.path.join(KEY_DIR, "password.key")\n\nencryption_key = None\n\ndef ensure_directories_exist():\n    os.makedirs(KEY_DIR, exist_ok=True)\n    os.makedirs(FILE_DIR, exist_ok=True)\n\ndef hash_password(password):\n    return hashlib.sha256(password.encode()).hexdigest()\n\ndef save_password(password_hash):\n    with open(PASSWORD_FILE, "w") as f:\n        f.write(password_hash)\n\ndef verify_password(input_password):\n    if not os.path.exists(PASSWORD_FILE):\n        return False\n    with open(PASSWORD_FILE, "r") as f:\n        stored_password_hash = f.read()\n    return stored_password_hash == hash_password(input_password)\n\ndef random_key():\n    return Fernet.generate_key()\n\ndef load_or_generate_key(input_password):\n    global encryption_key\n    key_file = os.path.join(KEY_DIR, "encryption_key.key")\n    password_hash = hash_password(input_password)\n\n    if os.path.exists(key_file):\n        with open(key_file, "rb") as keyfile:\n            encryption_key_encrypted = keyfile.read()\n        fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(password_hash.encode()).digest()))\n        try:\n            encryption_key = fernet.decrypt(encryption_key_encrypted)\n        except Exception as e:\n            messagebox.showerror("Error", "Incorrect password/key.")\n            return False\n    else:\n        encryption_key = random_key()\n        fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(password_hash.encode()).digest()))\n        encryption_key_encrypted = fernet.encrypt(encryption_key)\n        with open(key_file, "wb") as keyfile:\n            keyfile.write(encryption_key_encrypted)\n    \n    return True\n\ndef encrypt_file(file_path, show_encryption_message=True):\n    if not encryption_key:\n        messagebox.showerror("Error", "Encryption key not set.")\n        return\n    \n    with open(file_path, "rb") as file:\n        file_data = file.read()\n    \n    fernet = Fernet(encryption_key)\n    encrypted_data = fernet.encrypt(file_data)\n\n    file_name = os.path.basename(file_path)\n    encrypted_file_path = os.path.join(FILE_DIR, file_name + ".enc")\n    \n    with open(encrypted_file_path, "wb") as file:\n        file.write(encrypted_data)\n    \n    if show_encryption_message:\n        messagebox.showinfo("Success", f"File encrypted: {encrypted_file_path}")\n\ndef drag_and_drop(event):\n    file_paths = root.tk.splitlist(event.data)\n    for file_path in file_paths:\n        encrypt_file(file_path)\n\ndef decrypt_file(file_path):\n    if not encryption_key:\n        messagebox.showerror("Error", "Encryption key not set.")\n        return\n    \n    with open(file_path, "rb") as file:\n        encrypted_data = file.read()\n    \n    fernet = Fernet(encryption_key)\n    try:\n        decrypted_data = fernet.decrypt(encrypted_data)\n    except Exception as e:\n        messagebox.showerror("Error", f"Failed to decrypt file: {str(e)}")\n        return\n    \n    decrypted_file_path = file_path.replace(".enc", "")\n    \n    with open(decrypted_file_path, "wb") as file:\n        file.write(decrypted_data)\n    \n    return decrypted_file_path\n\ndef view_text(file_path):\n    with open(file_path, "r") as file:\n        content = file.read()\n    \n    viewer = Toplevel(root)\n    viewer.title(f"Viewing: {file_path}")\n    text_widget = Text(viewer, wrap="word")\n    text_widget.insert("1.0", content)\n    text_widget.pack(expand=True, fill="both")\n    viewer.protocol("WM_DELETE_WINDOW", lambda: (os.remove(file_path), viewer.destroy()))\n\ndef view_image(file_path):\n    viewer = Toplevel(root)\n    viewer.title(f"Viewing: {file_path}")\n    img = Image.open(file_path)\n    img = ImageTk.PhotoImage(img)\n    img_label = Label(viewer, image=img)\n    img_label.image = img\n    img_label.pack(expand=True, fill="both")\n\ndef view_encrypted_files():\n    file_list_window = Toplevel(root)\n    file_list_window.title("Encrypted Files")\n    file_list_window.geometry("400x250")\n\n    frame = tk.Frame(file_list_window)\n    frame.pack(fill="both", expand=True)\n\n    canvas = tk.Canvas(frame)\n    canvas.pack(side="left", fill="both", expand=True)\n\n    scrollbar = tk.Scrollbar(frame, orient="vertical", command=canvas.yview)\n    scrollbar.pack(side="right", fill="y")\n\n    canvas.configure(yscrollcommand=scrollbar.set)\n    canvas.bind(\'<Configure>\', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))\n\n    files_frame = tk.Frame(canvas)\n    canvas.create_window((0, 0), window=files_frame, anchor="nw")\n\n    files = [f for f in os.listdir(FILE_DIR) if f.endswith(".enc")]\n    for file_name in files:\n        def make_decrypt_view_callback(file_path):\n            def callback():\n                decrypted_file = decrypt_file(file_path)\n                if decrypted_file.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".ico", ".webp", ".svg")):\n                    view_image(decrypted_file)\n                else:\n                    view_text(decrypted_file)\n            return callback\n\n        file_path = os.path.join(FILE_DIR, file_name)\n        file_button = tk.Button(files_frame, text=file_name.split(".enc")[0], command=make_decrypt_view_callback(file_path))\n        file_button.pack(fill="both", padx=10, pady=5)\n\n    files_frame.update_idletasks()\n    canvas.configure(scrollregion=canvas.bbox("all"))\n\n\ndef change_password():\n    global encryption_key\n\n    current_password = simpledialog.askstring("Change Password", "Enter current password:", show=\'*\')\n    if not verify_password(current_password):\n        messagebox.showerror("Error", "Incorrect current password.")\n        return\n\n    new_password = simpledialog.askstring("Change Password", "Enter new password:", show=\'*\')\n    if not new_password:\n        messagebox.showerror("Error", "New password cannot be empty.")\n        return\n    \n    new_password_repeat = simpledialog.askstring("Change Password", "Repeat new password:", show=\'*\')\n    if new_password_repeat != new_password:\n        messagebox.showerror("Error", "Passwords do not match.")\n        return\n\n    new_password_hash = hash_password(new_password)\n\n    decrypted_files = []\n    files = [f for f in os.listdir(FILE_DIR) if f.endswith(".enc")]\n    for file_name in files:\n        file_path = os.path.join(FILE_DIR, file_name)\n        decrypted_file_path = decrypt_file(file_path)\n        if decrypted_file_path:\n            decrypted_files.append(decrypted_file_path)\n        os.remove(file_path)\n\n    fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(new_password_hash.encode()).digest()))\n    new_key = random_key()\n    encryption_key_encrypted = fernet.encrypt(new_key)\n    with open(os.path.join(KEY_DIR, "encryption_key.key"), "wb") as keyfile:\n        keyfile.write(encryption_key_encrypted)\n\n    encryption_key = new_key\n    for decrypted_file in decrypted_files:\n        encrypt_file(decrypted_file, False)\n        os.remove(decrypted_file)\n\n    save_password(new_password_hash)\n    messagebox.showinfo("Success", "Password changed successfully.")\n\ndef initial_setup():\n    if not os.path.exists(PASSWORD_FILE):\n        password = simpledialog.askstring("Set Password", "Please set a password for encryption:", show=\'*\')\n        if not password:\n            messagebox.showerror("Error", "Password cannot be empty.")\n            return False\n        \n        password_repeat = simpledialog.askstring("Change Password", "Repeat new password:", show=\'*\')\n        if password_repeat != password:\n            messagebox.showerror("Error", "Passwords do not match.")\n            return False\n\n        save_password(hash_password(password))\n        if not load_or_generate_key(password):\n            return False\n    else:\n        password = simpledialog.askstring("Enter Password", "Please enter your password:", show=\'*\')\n        if not verify_password(password):\n            messagebox.showerror("Error", "Incorrect password.")\n            return False\n        if not load_or_generate_key(password):\n            return False\n    load_or_generate_key(password)\n    return True\n\ndef setup_gui():\n    global root\n    root = TkinterDnD.Tk()\n    root.title("Drag and Drop Encryption")\n    root.geometry("400x200")\n\n    menu_bar = Menu(root)\n    file_menu = Menu(menu_bar, tearoff=0)\n    file_menu.add_command(label="View Encrypted Files", command=view_encrypted_files)\n    file_menu.add_command(label="Change Password", command=change_password)\n    menu_bar.add_cascade(label="File", menu=file_menu)\n    root.config(menu=menu_bar)\n\n    label = tk.Label(root, text="Drag and Drop files here to encrypt", padx=10, pady=10)\n    label.pack(expand=True, fill="both")\n\n    label.drop_target_register(DND_FILES)\n    label.dnd_bind(\'<<Drop>>\', drag_and_drop)\n\n    root.mainloop()\n\nif __name__ == "__main__":\n    ensure_directories_exist()\n    if initial_setup():\n        setup_gui()\n"""],
        }

        libraries = ["tkinterdnd2", "hashlib", "PIL", "base64", "cryptography", "requests", "subprocess"]

        for lib in libraries:
            self.progress_label.config(text=f"Installing {lib}...")
            self.update()
            try:
                __import__(lib)
            except ImportError:
                if lib == "PIL":
                    os.system(f"python -m pip install Pillow")
                    continue
                os.system(f"python -m pip install {lib}")
                os.system(f"python3 -m pip install {lib}")
            
            self.progress_label.config(text=f"Successfully installed {lib}.")
            self.update()

        try:
            os.mkdir(os.path.join(install_path, "FishyCrypter/"))
            for filename, content in files_to_download.items():
                if filename == "ManualWrite":
                    with open(os.path.join(install_path, "FishyCrypter/", content[0]), "w") as f:
                        f.write(content[1])
                else:
                    self.download_file(content, os.path.join(install_path, "FishyCrypter/", filename))
                self.progress_label.config(text=f"Downloaded {filename}")
                self.update()

            self.progress_label.config(text=f"Installation completed!")
            self.update()

            messagebox.showinfo("Success", "Installation completed successfully!")
            exit()
        except Exception as e:
            messagebox.showerror("Error", f"Installation failed: {e}")
            exit()

    def download_file(self, url, save_path):
        response = requests.get(url, stream=True)
        response.raise_for_status()

        with open(save_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    file.write(chunk)

if __name__ == "__main__":
    app = InstallerApp()
    app.mainloop()
