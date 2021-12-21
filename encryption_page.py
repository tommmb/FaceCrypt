import tkinter as tk
import os
from tkinter import messagebox
import hashlib
from aes import AES
# from main_page import MainPage
import main_page


class EncryptionPage(tk.Frame):
    def __init__(self, master):
        grey = master.grey
        tk.Frame.__init__(self, master, bg=grey)
        title_label = tk.Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        title_label.grid(column=0, row=0, pady=40, ipadx=10, ipady=5, columnspan=3)

        encryption_title = tk.StringVar()
        encryption_type = tk.StringVar()
        if self.master.is_encrypted:
            encryption_title.set('Confirm Decryption')
            encryption_type.set('Decrypt')
        else:
            encryption_title.set('Confirm Encryption')
            encryption_type.set('Encrypt')

        encryption_title = tk.Label(self, textvariable=encryption_title, font=('Arial', 14), bg=grey)
        encryption_title.grid(column=0, row=1, columnspan=3, pady=30)

        password = tk.StringVar()
        password_label = tk.Label(self, text='Password:', bg=grey, font=('Arial', 11))
        password_label.grid(column=0, row=2, pady=5)

        confirm_password = tk.StringVar()
        confirm_password_label = tk.Label(self, text='Confirm Password:', bg=grey, font=('Arial', 11))
        confirm_password_label.grid(column=0, row=3, pady=5)

        confirm_password_field = tk.Entry(self, textvariable=confirm_password, show='\u2022', width=25,
                                          font=('Arial', 12))
        confirm_password_field.configure(highlightbackground=grey)
        confirm_password_field.grid(column=1, row=3, pady=10, columnspan=2, padx=10)

        password_field = tk.Entry(self, textvariable=password, show='\u2022', width=25, font=('Arial', 12))
        password_field.configure(highlightbackground=grey)
        password_field.grid(column=1, row=2, pady=10, columnspan=2)

        encrypt_button = tk.Button(self, textvariable=encryption_type,
                                   command=lambda password=password, confirm_password=confirm_password:
                                   self.convert(password, confirm_password), font=('Arial', 11), width=12, bg='#A9D7FF')
        encrypt_button.grid(column=0, row=4, pady=55)

        cancel_button = tk.Button(self, text='Cancel', command=self.cancel, font=('Arial', 11), width=12, bg='#D11A2A')
        cancel_button.grid(column=2, row=4)

    def convert(self, password, confirm_password):
        password = password.get()
        confirm_password = confirm_password.get()

        if len(password) < 1 or len(confirm_password) < 1:
            messagebox.showwarning('Password Error', 'Password fields cannot be empty')
            return

        if password != confirm_password:
            messagebox.showwarning('Password Error', 'Passwords do not match.')
            return

        key = hashlib.md5(password.encode('utf-8')).digest()

        if self.master.file_in_db:
            query = 'SELECT iv FROM EncryptionData WHERE file_name = "%s"' % self.master.file_name
            self.master.cursor.execute(query)
            iv_hex = self.master.cursor.fetchone()[0]
            iv = bytes.fromhex(iv_hex)
            self.decrypt(key, iv)
        else:
            self.encrypt(key)

    def encrypt(self, key):
        text = self.master.master_text
        iv = os.urandom(16)
        encrypted_array = AES(key).encrypt_cbc(text, iv)

        select_id = 'SELECT id FROM Logins WHERE email = "%s" LIMIT 1;' % self.master.account.email
        self.master.cursor.execute(select_id)
        id = self.master.cursor.fetchone()[0]

        try:
            query = 'INSERT INTO EncryptionData (user_id, file_name, isEncrypted, iv) VALUES ("%d", "%s", "%d", "%s");' % \
                    (id, self.master.file_name, 1, bytes(iv).hex())

            self.master.cursor.execute(query)
            self.master.db.commit()

            with open(self.master.file_path, mode='wb') as f:
                f.write(bytearray(encrypted_array))
                f.close()

            file = open(self.master.file_path, mode='rb')
            self.master.master_text = file.read()
            self.master.is_encrypted = True

            messagebox.showinfo('Success', f'The file was successfully encrypted.')

        except Exception as e:
            print(e)
            messagebox.showwarning('File Error', 'The selected file cannot be opened.')
            return

        self.master.switch_frame(main_page.MainPage)
        self.master.file_in_db = True

    def decrypt(self, key, iv):
        text = self.master.master_text
        try:
            decrypted_array = AES(key).decrypt_cbc(text, iv)
            plaintext = ''.join([chr(x) for x in decrypted_array])

            query = 'SELECT id FROM Logins WHERE email = "%s" LIMIT 1;' % self.master.account.email
            self.master.cursor.execute(query)
            id = self.master.cursor.fetchone()[0]

            query2 = 'DELETE FROM EncryptionData WHERE user_id = "%d" AND file_name = "%s";' % (id, self.master.file_name)
            self.master.cursor.execute(query2)
            self.master.db.commit()

            with open(self.master.file_path, mode='w') as f:
                f.write(plaintext)
                f.close()

            file = open(self.master.file_path, mode='r')
            self.master.master_text = plaintext
            self.master.is_encrypted = False

            messagebox.showinfo('Success', f'The file was successfully decrypted.')
            self.master.file_in_db = False

        except Exception as e:
            print(e)
            messagebox.showwarning('Decryption Error', 'Incorrect password.')
            return

        self.master.switch_frame(main_page.MainPage)

    def cancel(self):
        self.master.switch_frame(main_page.MainPage)
