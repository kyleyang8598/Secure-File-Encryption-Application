import tkinter as tk
from tkinter import filedialog, messagebox
from encryption import AESCipher
import ClientSide


class EncryptionPage:
    """
    A GUI application for file encryption and decryption using AES or XOR methods.
    """

    def __init__(self, root: tk.Tk, key: bytes, email: str, password: str):
        """
        Initializes the GUI elements and variables.

        :param root: The main Tkinter window.
        """
        self.root = root
        self.root.title("File Encryption GUI")
        self.root.geometry("400x300")

        # Variables to store user inputs
        self.key = key
        self.email = email
        self.password = password
        self.method = tk.StringVar(value="AES")  # Default method is AES

        # File Selection UI
        tk.Label(root, text="Selected File:").pack()
        self.file_listbox = tk.Listbox(root, width=50, height=5)
        self.file_listbox.pack(pady=5)
        tk.Button(root, text="Browse", command=self.browse_file).pack()

        # Encryption Method Selection UI
        tk.Label(root, text="Encryption Method:").pack(pady=5)
        tk.Radiobutton(root, text="AES", variable=self.method, value="AES").pack()

        # Encrypt/Decrypt Buttons
        tk.Button(root, text="Encrypt", command=self.encrypt).pack(pady=10)
        tk.Button(root, text="Decrypt", command=self.decrypt).pack()

        # Add Account Menu
        menubar = tk.Menu(self.root)
        account_menu = tk.Menu(menubar, tearoff=0)
        account_menu.add_command(label="Delete Account", command=self.delete_account)
        account_menu.add_command(label="Change Password", command=self.change_password)
        account_menu.add_command(label="Logout", command=self.logout)

        menubar.add_cascade(label="👤 Account", menu=account_menu)
        self.root.config(menu=menubar)

    def browse_file(self):
        """
        Opens a file dialog for the user to select a file and sets the file path.
        """
        files = filedialog.askopenfilenames(title="Select Files", filetypes=[("All files", "*.*")])
        if files:
            self.file_paths = list(files)
            self.file_listbox.delete(0, tk.END)
            for f in self.file_paths:
                self.file_listbox.insert(tk.END, f)

    def encrypt(self):
        """
        Encrypts the selected file using the chosen encryption method (AES or XOR).
        Displays success or error messages using message boxes.
        """
        key = self.key
        email = self.email
        method = self.method.get()

        if not hasattr(self, 'file_paths') or not self.file_paths:
            messagebox.showwarning("Missing File", "Please select a file.")
            return

        try:
            if method == "AES":
                # Create AESCipher instance with key (auto-generated if not provided)
                for file in self.file_paths:
                    cipher = AESCipher(file, key, email)
                    self.file_paths[self.file_paths.index(file)] = cipher.encrypt()
                messagebox.showinfo("Success", f"AES encryption complete.")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        """
        Decrypts the selected file using the chosen method.
        Only AES decryption is implemented; XOR decryption is a placeholder.
        """
        key = self.key
        email = self.email
        method = self.method.get()

        if not hasattr(self, 'file_paths') or not self.file_paths:
            messagebox.showwarning("Missing File", "Please select one or more files.")
            return

        try:
            if method == "AES":
                # AES decryption requires a key
                for file in self.file_paths:
                    cipher = AESCipher(file, key, email)
                    cipher.decrypt()
                messagebox.showinfo("Success", "AES decryption complete.")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def logout(self):
        """
        Logs the user out by confirming and then closing the encryption page.
        """
        if messagebox.askyesno("Logout", "Are you sure you want to log out?"):
            self.root.destroy()  # This closes the current encryption window

            # Reopen login window
            new_root = tk.Tk()
            from login import AccountGUI
            AccountGUI(new_root)
            new_root.mainloop()

    def delete_account(self):
        """
        Opens a new page to change the user's email.
        """
        new_root = tk.Toplevel(self.root)
        DeleteAccount(root=new_root, current_email=self.email, parent_root=self.root, key=self.key, password=self.password)
        new_root.mainloop()

    def change_password(self):
        """
        Opens a new page to change the user's password.
        """
        new_root = tk.Toplevel(self.root)
        ChangePasswordPage(root=new_root, parent=self.root, email=self.email, password=self.password, key=self.key)
        new_root.mainloop()


class DeleteAccount:
    """
    A page for deleting user account.
    """

    def __init__(self, root: tk.Tk, current_email: str, parent_root: tk.Tk, key: bytes, password: str):
        
        self.root = root
        self.parent = parent_root
        self.root.title("Delete Account")
        self.root.geometry("300x200")

        # User Secrets
        self.current_email = current_email
        self.key = key
        self.password = password

        # Current Email Label
        tk.Label(root, text="Current Email:").pack(pady=5)
        self.current_email_label = tk.Label(root, text=self.current_email)
        self.current_email_label.pack(pady=5)

        # New Email Input
        tk.Label(root, text="To Delete Account Type \"CONFIRM DELETE\":").pack(pady=5)
        self.confirm = tk.Entry(root, width=30)
        self.confirm.pack(pady=5)

        # Submit Button
        tk.Button(root, text="Submit", command=self.submit).pack(pady=10)

    def submit(self):
        """
        Validates and submits the new email.
        """
        confirm = self.confirm.get()
        if confirm == 'CONFIRM DELETE':
            # Delete in the database
            message = f'delete:{self.current_email}:{self.password}'
            client = ClientSide.SecureTCPClient()
            client.encryptedSend(message)

            # Decrypt all files
            AESCipher(file=None, key=self.key, email=self.current_email).decrypt_all()

            messagebox.showinfo("Success", "Account successfully deleted!")
            self.parent.destroy()

            # Reopen login window
            new_root = tk.Tk()
            from login import AccountGUI
            AccountGUI(new_root)
            new_root.mainloop()
            return
        
        messagebox.showwarning("Invalid", "Please enter the confirmation.")
        return



class ChangePasswordPage:
    """
    A page for changing the user's password.
    """

    def __init__(self, root: tk.Tk, parent: tk.Tk, email: str, password: str, key: bytes):
        self.root = root
        self.parent = parent
        self.root.title("Change Password")
        self.root.geometry("300x250")

        # User Secrets 
        self.email = email
        self.password = password
        self.key = key

        # Current Password Input
        tk.Label(root, text="Current Password:").pack(pady=5)
        self.current_password_entry = tk.Entry(root, width=30, show="*")
        self.current_password_entry.pack(pady=5)

        # New Password Input
        tk.Label(root, text="New Password:").pack(pady=5)
        self.new_password_entry = tk.Entry(root, width=30, show="*")
        self.new_password_entry.pack(pady=5)

        # Confirm New Password Input
        tk.Label(root, text="Confirm New Password:").pack(pady=5)
        self.confirm_password_entry = tk.Entry(root, width=30, show="*")
        self.confirm_password_entry.pack(pady=5)

        # Submit Button
        tk.Button(root, text="Submit", command=self.submit).pack(pady=10)

    def submit(self):
        """
        Validates and submits the new password.
        """
        current_password = self.current_password_entry.get()
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not current_password or not new_password or not confirm_password:
            messagebox.showwarning("Incomplete Fields", "Please fill out all fields.")
            return

        if new_password != confirm_password:
            messagebox.showwarning("Password Mismatch", "The new passwords do not match.")
            return

        # Update password in the database (dummy logic for now)
        message = f'change:{self.email}:{current_password}:{new_password}'
        client = ClientSide.SecureTCPClient()
        client.encryptedSend(message)
        # Decrypt all files
        AESCipher(file=None, key=self.key, email=self.email).decrypt_all()

        # Encrypt all files with new password
        import login
        account = login.Account()
        code = account.login(email=self.email, password=new_password, recovery=False)

        if code.startswith("Welcome"):
            AESCipher(file=None, key=account.EncryptionKey, email=self.email).encrypt_all()
            messagebox.showinfo("Success", "Password successfully updated!")
            self.parent.destroy()

            # Reopen login window
            new_root = tk.Tk()
            from login import AccountGUI
            AccountGUI(new_root)
            new_root.mainloop()

        else:
            messagebox.showinfo("Failed", "Password failed to update!")
            self.root.destroy()


if __name__ == "__main__":
    # Entry point for the application
    root = tk.Tk()
    key = b'your-32-byte-key-goes-here-123456789012'
    email = "example@example.com"
    app = EncryptionPage(root, key, email)
    root.mainloop()
