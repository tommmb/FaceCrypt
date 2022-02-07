import tkinter as tk
import os
from tkinter import filedialog, messagebox
import windows.login_page as login_page
from windows.encryption_page import EncryptionPage
from windows.settings_page import SettingsPage


class MainPage(tk.Frame):
    def __init__(self, master):
        grey = master.grey
        tk.Frame.__init__(self, master, bg=grey)
        self.email = tk.StringVar(value=self.master.account.email)

        # title_label = tk.Label(self, text='FaceCrypt', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        # title_label.grid(column=0, row=1, pady=80, ipadx=10, ipady=5, columnspan=5, rowspan=2)

        settings = tk.Button(self, text='Account Settings', command=self.open_settings)
        settings.grid(column=0, row=0, pady=(15, 100))

        account = tk.Label(self, textvariable=self.email, font=('Arial', 10), bg=grey)
        account.grid(column=3, row=0, pady=(15, 100))

        logout = tk.Button(self, text='Sign out', command=self.log_out)
        logout.grid(column=4, row=0, pady=(15, 100))

        self.filename = tk.StringVar()
        if self.master.file_name == '':
            self.filename.set('No File Selected')
        else:
            self.filename.set(self.master.file_name)

        file_label = tk.Label(self, text='Selected File: ', font=('Arial', 11), bg=grey)
        file_label.grid(column=0, row=2)
        file_name = tk.Label(self, textvariable=self.filename, font=('Arial', 11), bg=grey, fg='#7d7d7d')
        file_name.grid(column=1, row=2)
        file_select = tk.Button(self, text='Select File', command=self.select_file, font=('Arial', 10), bg=grey)
        file_select.grid(column=2, row=2)

        self.encrypted = tk.StringVar()
        if self.master.is_encrypted:
            self.encrypted.set('True')
        else:
            self.encrypted.set('False')

        self.encrypt_decrypt = tk.StringVar()

        if self.master.is_encrypted:
            self.encrypt_decrypt.set('Decrypt')
        else:
            self.encrypt_decrypt.set('Encrypt')

        encryption_status_label = tk.Label(self, text='Encryption Status:', font=('Arial', 11), bg=grey)
        encryption_status_label.grid(column=0, row=3, pady=10)
        encryption_status = tk.Label(self, textvariable=self.encrypted, font=('Arial', 11), bg=grey, fg='#ba0000')
        encryption_status.grid(column=1, row=3)
        encrypt_file_button = tk.Button(self, textvariable=self.encrypt_decrypt, command=self.encrypt_or_decrypt,
                                     font=('Arial', 10), bg=grey)
        encrypt_file_button.grid(column=2, row=3)

        self.text = tk.Text(self, height=15, width=100, pady=10)
        self.text.insert(1.0, self.master.master_text)
        self.text.config(state=tk.DISABLED)
        self.text.grid(column=0, row=4, columnspan=5)

    def select_file(self):
        filetypes = (
            ('Text Documents', '*.txt'),
            # ('Unicode Documents', '*.utf8'),
            ('All files', '*.*')
        )

        file = filedialog.askopenfile(filetypes=filetypes)
        if file is None:
            return

        query = 'SELECT file_name, isEncrypted FROM EncryptionData WHERE file_name = "%s" LIMIT 1;' % file.name
        self.master.cursor.execute(query)
        result = self.master.cursor.fetchone()

        self.master.file_name = file.name

        if result is not None:
            self.master.file_in_db = True
            if result[1] == 1:
                self.master.is_encrypted = True
            if result[1] == 0:
                self.master.is_encrypted = False
        else:
            self.master.is_encrypted = False

        try:
            if self.master.file_in_db:
                file = open(file.name, mode='rb')
                self.master.master_text = file.read()
            else:
                file = open(file.name, mode='r')
                self.master.master_text = file.read()
        except Exception as e:
            print(e)
            messagebox.showwarning('File Error', 'The selected file cannot be opened.')
            return

        self.text.config(state=tk.NORMAL)
        self.text.delete(1.0, tk.END)
        self.text.insert(1.0, self.master.master_text)
        self.filename.set(os.path.basename(file.name))
        self.master.file_path = file.name
        self.text.config(state=tk.DISABLED)
        self.master.switch_frame(MainPage)

    def log_out(self):
        answer = messagebox.askyesno('Sign Out', 'Are you sure you want to sign out?')

        if answer:
            self.master.file_name = ''
            self.master.master_text = ''
            self.master.is_encrypted = False
            self.master.switch_frame(login_page.LoginPage)
            self.email.set('')
            return

    def encrypt_or_decrypt(self):
        if self.master.master_text == '':
            messagebox.showwarning('Encryption Error', 'No File Selected')
            return
        self.master.switch_frame(EncryptionPage)

    def open_settings(self):
        self.master.switch_frame(SettingsPage)
