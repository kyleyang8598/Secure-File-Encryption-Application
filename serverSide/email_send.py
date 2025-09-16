from simplegmail import Gmail

class tempPassword():
    def __init__(self, email:str, temp_password:str):
        self.gmail = Gmail()
        self.temp_password = temp_password
        self.message = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
                    <div style="background-color: #fff; padding: 20px; border-radius: 8px; max-width: 600px; margin: auto;">
                        <h2 style="color: #333;">Temporary Password Request</h2>
                        <p>Hello,</p>
                        <p>You've requested a temporary password to log into your account.</p>
                        <p style="font-size: 18px; font-weight: bold; background-color: #f0f0f0; padding: 10px; border-radius: 5px; text-align: center;">
                            <span>{self.temp_password}</span>
                        </p>
                        <p>Please use this temporary password to log in and reset your password immediately for security reasons.</p>
                        <p style="font-size: 12px; color: #777;">If you did not request this, please ignore this email or contact support.</p>
                    </div>
            </body>
        </html>
        """
        self.params = {
            "to": email,
            "sender": "securephraserecovery@gmail.com",
            "subject": "Temporary Password",
            "msg_html":  self.message,
            "msg_plain": f"Your temporary password is: {self.temp_password}. Use it to log in and reset your password immediately.",
            "signature": True  # use my account signature
            }
        
    def sendEmail(self):
        self.gmail.send_message(**self.params)

if __name__ == "__main__":
    email = tempPassword('nlim2@gmu.edu', 'testing')
    email.sendEmail()