import tkinter as tk
from tkinter import messagebox
import re

class PasswordRecoveryPage:
    def __init__(self, root:tk.Tk, account):
        self.account = account
        self.root = root
        self.root.title("Password Recovery")
        self.root.geometry("400x500")

        tk.Label(root, text="Recover Password", font=("Helvetica", 16)).pack(pady=10)

        tk.Label(root, text="Enter your email address:").pack()
        self.email_entry = tk.Entry(root, width=40)
        self.email_entry.pack(pady=5)

        tk.Button(root, text="Submit", command=self.submit_email).pack(pady=10)
        tk.Button(root, text="Back", command=self.go_back).pack()

        # Temporary password field (initially hidden)
        self.temp_password_label = None
        self.temp_password_entry = None


    def submit_email(self):
        email = self.email_entry.get().strip()

        if not email:
            messagebox.showwarning("Missing Input", "Please enter your email.")
            return
        
        # Simple email format check
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showerror("Invalid Email", "Please enter a valid email address.")
            return

        # TODO: Send email to server for password recovery
        import login
        login.Account.forgot_password(self.account, email)

        # Show temporary password input box after email submission
        self.show_temp_password_box()

        messagebox.showinfo("Recovery", f"Password recovery instructions sent to {email}.")
    
    def show_temp_password_box(self):
        # Create the temporary password input box and label
        if not self.temp_password_label:  # Only create once
            self.temp_password_label = tk.Label(self.root, text="Enter the temporary password:")
            self.temp_password_label.pack()

            self.temp_password_entry = tk.Entry(self.root, width=40, show="*")
            self.temp_password_entry.pack(pady=5)

            # Change submit button to process temporary password
            submit_button = tk.Button(self.root, text="Submit Temp Password", command=self.submit_temp_password)
            submit_button.pack(pady=10)

    def submit_temp_password(self):
        temp_password = self.temp_password_entry.get().strip()

        if not temp_password:
            messagebox.showwarning("Missing Temp Password", "Please enter the temporary password.")
            return

        # Send the temporary password to the server for verification
        email = self.email_entry.get().strip()

        # Simulate checking the temp password with the server
        import login
        code = login.Account.login(self.account, f'recover-email:{email}', f'recover-password:{temp_password}', recovery=True)
        if code == 'password-reset':
            self.go_back()


    def go_back(self):
        self.root.destroy()
        from login import AccountGUI
        new_root = tk.Tk()
        AccountGUI(new_root)
        new_root.mainloop()
