"""Module to handle account login/creation"""

import tkinter as tk
from tkinter import messagebox
import ClientSide
import Crypto.Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
import base64
from encryption_page import EncryptionPage
import re

class Account:
    """
    Handles user account operations such as creation and login,
    and communicates with a secure TCP client for server interaction.
    """

    def __init__(self):
        self.email = None
        self.password = None
        self.client = ClientSide.SecureTCPClient()
        self.key = Crypto.Random.get_random_bytes(32)
        self.EncryptionKey = None

    def createAccount(self, email, email_confirm, password, password_confirm):
        """
        Creates a new account if the email and password fields match their confirmation fields.

        Args:
            email (str): Email address.
            email_confirm (str): Email confirmation.
            password (str): Password.
            password_confirm (str): Password confirmation.

        Returns:
            str: Result message of the account creation attempt.
        """
        if email != email_confirm or password != password_confirm:
            return "Email or Password does not match"
        
        # Make sure email account is legit
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
           return "Invalid Email: Please enter a valid email address."

        self.client.encryptedSend(f'create-email:{email}:create-password:{password}')
        return "Account created successfully!"

    def login(self, email:str, password:str, recovery=False):
        """
        Attempts to log in with the given credentials.

        Args:
            email (str): Email address.
            password (str): Password.

        Returns:
            str: Result message of the login attempt.
        """
        if recovery:
            AESkey = base64.b64encode(self.key).decode()
            message = f'{email}:{password}:{AESkey}'
            self.client.encryptedSend(message)
            code = self.client.encryptedRecieve().split(':')
            if '200' in code:
                import encryption
                key_encrypted = base64.b64decode(code[-1])
                key_unencrypted = self.decrypt(key_encrypted)
                self.EncryptionKey = SHA256.new(key_unencrypted).digest()
                encryption.AESCipher(file=None, key=self.EncryptionKey, email=email.split(':')[-1]).decrypt_all()
                return 'password-reset'

        else:
            self.email = f'email:{email}'
            self.password = f'password:{password}'
            key = base64.b64encode(self.key).decode()

            self.client.encryptedSend(f'{self.email}:{self.password}:{key}')
            code = self.client.encryptedRecieve().split(':')

            if '200' in code:
                key_encrypted = base64.b64decode(code[-1])
                key_unencrypted = self.decrypt(key_encrypted)
                self.EncryptionKey = SHA256.new(key_unencrypted).digest()
                return f"Welcome, {email}!"
            elif '404' in code:
                return "Incorrect Email or Password."
            else:
                print(code)
                return "ERROR: something unexpected happened."
        
    def forgot_password(self, email:str):
        self.client.encryptedSend(f'recover-email:{email}')

        
    def decrypt(self, content):
        ciphertext = content
        iv = ciphertext[:AES.block_size] # change later include SHA256 for Key generation and IV
        ciphertext = ciphertext[AES.block_size:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    

class AccountGUI:
    """
    GUI application for user login and account creation using Tkinter.
    """

    def __init__(self, root:tk.Tk):
        self.account = Account()
        self.root = root
        self.root.title("Account Login System")
        self.root.geometry("400x300")
        self.login_screen()

    def clear_frame(self):
        """Removes all widgets from the current window frame."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def login_screen(self):
        """Displays the login screen with email and password fields."""
        self.clear_frame()
        tk.Label(self.root, text="Login", font=("Helvetica", 16)).pack(pady=10)

        email_entry = self.create_entry("Email:")
        password_entry = self.create_entry("Password:", show="*")

        tk.Button(self.root, text="Login",
                  command=lambda: self.login_action(email_entry.get(), password_entry.get())).pack(pady=10)
        
        tk.Button(self.root, text="Create Account", command=self.create_account_screen).pack()

        tk.Button(self.root, text="Forgot Password?", command=self.forgot_password).pack(pady=5)



    def create_account_screen(self):
        """Displays the account creation screen with confirmation fields."""
        self.clear_frame()
        tk.Label(self.root, text="Create Account", font=("Helvetica", 16)).pack(pady=10)

        email_entry = self.create_entry("Email:")
        email_confirm_entry = self.create_entry("Confirm Email:")
        password_entry = self.create_entry("Password:", show="*")
        password_confirm_entry = self.create_entry("Confirm Password:", show="*")

        tk.Button(
            self.root,
            text="Create",
            command=lambda: self.create_action(
                email_entry.get(),
                email_confirm_entry.get(),
                password_entry.get(),
                password_confirm_entry.get()
            )
        ).pack(pady=10)

        tk.Button(self.root, text="Back to Login", command=self.login_screen).pack()

    def create_entry(self, label, show=None):
        """
        Helper method to create a labeled entry field.

        Args:
            label (str): The label text.
            show (str, optional): Character to show instead of actual text (e.g., '*' for passwords).

        Returns:
            tk.Entry: The created entry widget.
        """
        tk.Label(self.root, text=label).pack()
        entry = tk.Entry(self.root, show=show)
        entry.pack()
        return entry

    def login_action(self, email, password):
        """
        Executes the login action and shows a result message.

        Args:
            email (str): Email address input.
            password (str): Password input.
        """
        message = self.account.login(email, password)
        if message.startswith("Welcome"):
            messagebox.showinfo("Login", message)

            # Close the login window
            self.root.destroy()

            # Open the EncryptionPage in a new window with the key
            new_root = tk.Tk()
            EncryptionPage(new_root, self.account.EncryptionKey, email, password)
            new_root.mainloop()

        else:
            messagebox.showerror("Login Failed", message)

    def create_action(self, email, email_conf, password, password_conf):
        """
        Executes the account creation action and shows a result message.

        Args:
            email (str): Email input.
            email_conf (str): Email confirmation input.
            password (str): Password input.
            password_conf (str): Password confirmation input.
        """
        message = self.account.createAccount(email, email_conf, password, password_conf)
        messagebox.showinfo("Create Account", message)
        if message == "Account created successfully!":
            self.login_screen()

    def forgot_password(self):
        """
        Handles 'Forgot Password' action.
        For now, it shows a placeholder. You can expand this later.
        """
        self.root.destroy()
        from password_recovery import PasswordRecoveryPage
        new_root = tk.Tk()
        PasswordRecoveryPage(new_root, self.account)
        new_root.mainloop()


        
# Run the GUI application
if __name__ == "__main__":
    root = tk.Tk()
    app = AccountGUI(root)
    root.mainloop()
