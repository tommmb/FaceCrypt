from tkinter import PhotoImage
from tkinter import Tk, IntVar
from tkinter import Frame
from tkinter import Label
from tkinter import Entry
from tkinter import Button
from tkinter import Text
from tkinter import StringVar
from tkinter import messagebox
from tkinter import filedialog
from tkinter import END
from tkinter import DISABLED
from tkinter import NORMAL
from mysql import connector
from bcrypt import gensalt, hashpw
from re import search
from os.path import basename
from aes import AES
from hashlib import md5
from os import urandom
import os
from PIL import Image
from PIL import ImageTk
import numpy as np
import cv2
import cv2.data as data
import pickle


class App(Tk):
    def __init__(self):
        self.grey = '#CDCDCD'
        self.db = connector.connect(
            host="localhost",
            user="root",
            passwd="root",
            database='project'
        )

        self.cursor = self.db.cursor(buffered=True)

        Tk.__init__(self)
        self.geometry('1000x700')
        self.resizable(0, 0)
        self.title('Project Name')
        self.configure(bg=self.grey)
        self._frame = None
        self.file_name = ''
        self.master_text = ''
        self.is_encrypted = False
        self.account = Account(1, 'tom@gmail.com', 'tom', 'burke')
        self.switch_frame(LoginPage)
        self.file_in_db = False

    def switch_frame(self, frame_class):
        new_frame = frame_class(self)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.pack()


def capitalise(word):
    assert len(word) > 0
    return word[0].upper() + word[1:len(word)]


class LoginPage(Frame):
    def __init__(self, master):
        grey = master.grey
        Frame.__init__(self, master, bg=grey)

        """ Title """
        title_label = Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        title_label.grid(column=1, row=0, pady=80, ipadx=10, ipady=5)

        email = StringVar()
        email_label = Label(self, text='Email:', bg=grey, font=('Arial', 10))
        email_label.grid(column=0, row=1, pady=10)
        email_field = Entry(self, textvariable=email, width=37, font=('Arial', 12))
        email_field.configure(highlightbackground=grey)
        email_field.grid(column=1, row=1, pady=10)

        password = StringVar()
        password_label = Label(self, text='Password:', bg=grey, font=('Arial', 10))
        password_label.grid(column=0, row=2, pady=5)
        password_field = Entry(self, textvariable=password, show='\u2022', width=37, font=('Arial', 12))
        password_field.grid(column=1, row=2, pady=10)

        login_button = Button(self, text='Sign In', bg='#A9D7FF', font=('Arial', 11),
                              command=lambda email=email_field, password=password_field: self.login(email, password))
        login_button.configure(highlightbackground=grey)
        login_button.grid(column=1, row=3, ipadx=145, pady=20)

        register_label = Label(self, text="Don't have an account?", bg=grey, font=('Arial', 10)) \
            .grid(column=1, row=4, pady=10, columnspan=2)
        register_button = Button(self, text='Register', command=lambda: master.switch_frame(RegisterPage), width=10,
                                 font=('Arial', 10))
        register_button.configure(highlightbackground=grey)
        register_button.grid(column=1, row=5)

    def login(self, _email, _password):
        email, password = _email.get().strip(), _password.get().strip()
        if len(email) < 1:
            messagebox.showwarning('Email Error', 'Please enter an email.')
            return
        elif len(password) < 1:
            messagebox.showwarning('Password Error', 'Please enter a password.')
            return

        regex = search("^[^@\s]+@[^@\s]+\.[^@\s]+$", email)
        if regex is None:
            messagebox.showwarning('Email Error', 'Please enter a valid email.')
            return

        try:
            email = regex.group(0)
            salt_query = 'SELECT salt FROM Logins WHERE email = "%s" LIMIT 1;' % email
            self.master.cursor.execute(salt_query)
            salt = self.master.cursor.fetchone()[0]

            hashed = hashpw(bytes(password, 'utf-8'), salt.encode('utf-8')).decode('utf-8')
            query = 'SELECT id FROM Logins WHERE email = "%s" AND password = "%s" LIMIT 1;' % (email, hashed)
            self.master.cursor.execute(query)
            id = self.master.cursor.fetchone()

            query2 = 'SELECT first_name, last_name FROM Users WHERE user_id="%s"' % id
            self.master.cursor.execute(query2)
            result = self.master.cursor.fetchone()

            if result is None:
                raise Exception

            # successfully logged in

            self.master.account = Account(id, email, result[0], result[1])
            self.master.switch_frame(MainPage)

        except Exception as a:
            print(a)
            messagebox.showwarning('Sign in Error', 'Incorrect email or password')
            return


class RegisterPage(Frame):
    def __init__(self, master):
        grey = master.grey
        Frame.__init__(self, master, bg=grey)

        title_label = Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        title_label.grid(column=0, row=0, pady=80, ipadx=10, ipady=5, columnspan=4)

        email = StringVar()
        email_label = Label(self, text='Email:', bg=grey, font=('Arial', 10)).grid(column=0, row=1, pady=10, padx=10)
        email_field = Entry(self, textvariable=email, width=25, font=('Arial', 12))
        email_field.configure(highlightbackground=grey)
        email_field.grid(column=1, row=1, pady=10)

        password = StringVar()
        password_label = Label(self, text='Password:', bg=grey, font=('Arial', 10)).grid(column=0, row=2, pady=5,
                                                                                         padx=10)
        password_field = Entry(self, textvariable=password, show='\u2022', width=25, font=('Arial', 12))
        password_field.configure(highlightbackground=grey)
        password_field.grid(column=1, row=2, pady=10)

        confirm_password = StringVar()

        confirm_password_label = Label(self, text='Confirm Password:', bg=grey, font=('Arial', 10))
        confirm_password_label.grid(column=0, row=3, pady=10, padx=10)
        confirm_password_field = Entry(self, textvariable=confirm_password, show='\u2022', width=25, font=('Arial', 12))
        confirm_password_field.configure(highlightbackground=grey)
        confirm_password_field.grid(column=1, row=3, pady=10)

        first_name = StringVar()
        first_name_label = Label(self, text='First Name:', bg=grey, font=('Arial', 10))
        first_name_label.grid(column=2, row=1, padx=20)
        first_name_field = Entry(self, textvariable=first_name, width=25, font=('Arial', 12))
        first_name_field.configure(highlightbackground=grey)
        first_name_field.grid(column=3, row=1, padx=5, pady=10)

        last_name = StringVar()
        last_name_label = Label(self, text='Last Name:', bg=grey, font=('Arial', 10))
        last_name_label.grid(column=2, row=2, padx=20)
        last_name_field = Entry(self, textvariable=last_name, width=25, font=('Arial', 12))
        last_name_field.configure(highlightbackground=grey)
        last_name_field.grid(column=3, row=2, padx=5, pady=10)

        register_button = Button(self, text='Register', bg='#A9D7FF', width=30, font=('Arial', 11),
                                 command=lambda _email=email_field, _password=password_field,
                                                _confirm_password=confirm_password_field, _first_name=first_name_field,
                                                _last_name=last_name_field:
                                 self.register(_email, _password, _confirm_password, _first_name, _last_name))
        register_button.configure(highlightbackground=grey)
        register_button.grid(column=0, row=4, columnspan=4, pady=20)

        login_label = Label(self, text="Already have an account?", bg=grey, font=('Arial', 10))
        login_label.grid(column=0, row=5, pady=5, columnspan=4)
        login_button = Button(self, text='Sign In', command=lambda: master.switch_frame(LoginPage), font=('Arial', 10),
                              width=6)
        login_button.configure(highlightbackground=grey)
        login_button.grid(column=0, row=6, pady=5, columnspan=4)

    def register(self, email, password, confirm_password, first_name, last_name):
        email = email.get().strip()
        password = password.get().strip()
        confirm_password = confirm_password.get().strip()
        first_name = first_name.get().strip()
        last_name = last_name.get().strip()

        if len(email) < 1:
            messagebox.showwarning('Email Error', 'Please enter an email.')
            return
        elif len(first_name) < 1:
            messagebox.showwarning('Name Error', 'Please enter a first name.')
            return
        elif len(last_name) < 1:
            messagebox.showwarning('Name Error', 'Please enter a last name.')
            return
        elif len(password) < 1:
            messagebox.showwarning('Password Error', 'Please enter a password.')
            return
        elif len(confirm_password) < 1:
            messagebox.showwarning('Password Error', 'Please confirm your password.')
            return
        elif confirm_password != password:
            messagebox.showwarning('Password Error', 'Passwords do not match.')
            return

        regex = search("^[^@\s]+@[^@\s]+\.[^@\s]+$", email)
        if regex is None:
            messagebox.showwarning('Email Error', 'Please enter a valid email.')
            return
        try:
            email = regex.group(0)
            query = 'SELECT * FROM Logins WHERE email = "%s"' % email
            self.master.cursor.execute(query)
            result = self.master.cursor.fetchone()

            if result is not None:
                messagebox.showwarning('Registration Error', 'A user already exists with that email.')
                return
        except Exception as e:
            print(e)
            messagebox.showwarning('Registration Error', 'Something went wrong during registration.')
            return

        salt = gensalt(rounds=10).decode('utf-8')
        hashed = hashpw(bytes(password, 'utf-8'), salt.encode('utf-8')).decode('utf-8')

        try:
            query = 'INSERT INTO Logins (email, password, salt) ' \
                    'VALUES ("%s", "%s", "%s");' % (email, hashed, salt)
            self.master.cursor.execute(query)

            query2 = 'INSERT INTO Users(user_id, first_name, last_name, access_level) ' \
                     'VALUES (LAST_INSERT_ID(), "%s", "%s", "%s")' % (first_name, last_name, 'NORMAL')
            self.master.cursor.execute(query2)
            self.master.db.commit()

            messagebox.showinfo('Success', 'Successfully registered.')
            self.master.switch_frame(LoginPage)

        except Exception as e:
            print(e)
            messagebox.showwarning('Registration Error', 'Something went wrong during registration.')
            return


class MainPage(Frame):
    def __init__(self, master):
        grey = master.grey
        Frame.__init__(self, master, bg=grey)

        # title_label = Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        # title_label.grid(column=0, row=1, pady=80, ipadx=10, ipady=5, columnspan=5, rowspan=2)

        settings = Button(self, text='Account Settings', command=self.open_settings)
        settings.grid(column=0, row=0, pady=(15, 100))

        account = Label(self, text=self.master.account.email, font=('Arial', 10), bg=grey)
        account.grid(column=3, row=0, pady=(15, 100))

        logout = Button(self, text='Sign out', command=self.log_out)
        logout.grid(column=4, row=0, pady=(15, 100))

        self.filename = StringVar()
        if self.master.file_name == '':
            self.filename.set('No File Selected')
        else:
            self.filename.set(self.master.file_name)

        file_label = Label(self, text='Selected File: ', font=('Arial', 11), bg=grey)
        file_label.grid(column=0, row=2)
        file_name = Label(self, textvariable=self.filename, font=('Arial', 11), bg=grey, fg='#7d7d7d')
        file_name.grid(column=1, row=2)
        file_select = Button(self, text='Select File', command=self.select_file, font=('Arial', 10), bg=grey)
        file_select.grid(column=2, row=2)

        self.encrypted = StringVar()
        if self.master.is_encrypted:
            self.encrypted.set('True')
        else:
            self.encrypted.set('False')

        self.encrypt_decrypt = StringVar()

        if self.master.is_encrypted:
            self.encrypt_decrypt.set('Decrypt')
        else:
            self.encrypt_decrypt.set('Encrypt')

        encryption_status_label = Label(self, text='Encryption Status:', font=('Arial', 11), bg=grey)
        encryption_status_label.grid(column=0, row=3, pady=10)
        encryption_status = Label(self, textvariable=self.encrypted, font=('Arial', 11), bg=grey, fg='#ba0000')
        encryption_status.grid(column=1, row=3)
        encrypt_file_button = Button(self, textvariable=self.encrypt_decrypt, command=self.encrypt_or_decrypt,
                                     font=('Arial', 10), bg=grey)
        encrypt_file_button.grid(column=2, row=3)

        self.text = Text(self, height=15, width=100, pady=10)
        self.text.insert(1.0, self.master.master_text)
        self.text.config(state=DISABLED)
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
            file = open(file.name, mode='rb')
            self.master.master_text = file.read()
        except Exception as e:
            print(e)
            messagebox.showwarning('File Error', 'The selected file cannot be opened.')
            return

        self.text.config(state=NORMAL)
        self.text.delete(1.0, END)
        self.text.insert(1.0, self.master.master_text)
        self.filename.set(basename(file.name))
        self.master.file_path = file.name
        self.text.config(state=DISABLED)
        self.master.switch_frame(MainPage)

    def log_out(self):
        answer = messagebox.askyesno('Sign Out', 'Are you sure you want to sign out?')

        if answer:
            self.master.file_name = ''
            self.master.master_text = ''
            self.master.is_encrypted = False
            self.master.switch_frame(LoginPage)
            return

    def encrypt_or_decrypt(self):
        if self.master.master_text == '':
            messagebox.showwarning('Encryption Error', 'No File Selected')
            return
        self.master.switch_frame(EncryptionPage)

    def open_settings(self):
        self.master.switch_frame(SettingsPage)


class EncryptionPage(Frame):
    def __init__(self, master):
        grey = master.grey
        Frame.__init__(self, master, bg=grey)
        title_label = Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        title_label.grid(column=0, row=0, pady=40, ipadx=10, ipady=5, columnspan=3)

        encryption_title = StringVar()
        encryption_type = StringVar()
        if self.master.is_encrypted:
            encryption_title.set('Confirm Decryption')
            encryption_type.set('Decrypt')
        else:
            encryption_title.set('Confirm Encryption')
            encryption_type.set('Encrypt')

        encryption_title = Label(self, textvariable=encryption_title, font=('Arial', 14), bg=grey)
        encryption_title.grid(column=0, row=1, columnspan=3, pady=30)

        password = StringVar()
        password_label = Label(self, text='Password:', bg=grey, font=('Arial', 11))
        password_label.grid(column=0, row=2, pady=5)

        confirm_password = StringVar()
        confirm_password_label = Label(self, text='Confirm Password:', bg=grey, font=('Arial', 11))
        confirm_password_label.grid(column=0, row=3, pady=5)

        confirm_password_field = Entry(self, textvariable=confirm_password, show='\u2022', width=25, font=('Arial', 12))
        confirm_password_field.configure(highlightbackground=grey)
        confirm_password_field.grid(column=1, row=3, pady=10, columnspan=2, padx=10)

        password_field = Entry(self, textvariable=password, show='\u2022', width=25, font=('Arial', 12))
        password_field.configure(highlightbackground=grey)
        password_field.grid(column=1, row=2, pady=10, columnspan=2)

        encrypt_button = Button(self, textvariable=encryption_type,
                                command=lambda password=password, confirm_password=confirm_password:
                                self.convert(password, confirm_password), font=('Arial', 11), width=12, bg='#A9D7FF')
        encrypt_button.grid(column=0, row=4, pady=55)

        cancel_button = Button(self, text='Cancel', command=self.cancel, font=('Arial', 11), width=12, bg='#D11A2A')
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

        key = md5(password.encode('utf-8')).digest()

        if self.master.is_encrypted:
            query = 'SELECT iv FROM EncryptionData WHERE file_name = "%s"' % self.master.file_name
            self.master.cursor.execute(query)
            iv_hex = self.master.cursor.fetchone()[0]
            iv = bytearray.fromhex(iv_hex)
            self.decrypt(key, iv)
        else:
            self.encrypt(key)

    def encrypt(self, key):

        text = self.master.master_text.decode('utf-8')
        iv = urandom(16)
        encrypted_array = AES(key).encrypt_cbc(text, iv)

        select_id = 'SELECT id FROM Logins WHERE email = "%s" LIMIT 1;' % self.master.account.email
        self.master.cursor.execute(select_id)
        id = self.master.cursor.fetchone()[0]

        try:
            if self.master.file_in_db:
                # update record
                query = 'UPDATE TABLE EncryptionData SET isEncrypted = "%d" WHERE user_id = "%d" AND file_name = "%s";' % (
                    1, id, self.master.file_path)
            else:
                # insert record
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

        self.master.switch_frame(MainPage)

    def decrypt(self, key, iv):
        text = self.master.master_text
        try:
            decrypted_array = AES(key).decrypt_cbc(text, iv)
            plaintext = ''.join([chr(x) for x in decrypted_array])

            query = 'SELECT id FROM Logins WHERE email = "%s" LIMIT 1;' % self.master.account.email
            self.master.cursor.execute(query)
            id = self.master.cursor.fetchone()[0]

            print(self.master.file_path)
            query2 = 'UPDATE EncryptionData SET isEncrypted = "%d" WHERE user_id = "%d" AND file_name = "%s";' % (
                0, id, self.master.file_path)
            print(query2)
            self.master.cursor.execute(query2)
            self.master.db.commit()

            with open(self.master.file_path, mode='w') as f:
                f.write(plaintext)
                f.close()

            file = open(self.master.file_path, mode='rb')
            self.master.master_text = file.read()
            self.master.is_encrypted = False

            messagebox.showinfo('Success', f'The file was successfully decrypted.')

        except Exception as e:
            print(e)
            messagebox.showwarning('Decryption Error', 'Incorrect password.')
            return

        self.master.switch_frame(MainPage)

    def cancel(self):
        self.master.switch_frame(MainPage)


class SettingsPage(Frame):
    def __init__(self, master):
        grey = master.grey
        Frame.__init__(self, master, bg=grey)
        self.face_rec_enabled = StringVar(value='Disabled')
        self.change_face_rec_status = StringVar(value='Enable')

        title_label = Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        title_label.grid(column=0, row=0, pady=40, ipadx=10, ipady=5, columnspan=3)

        encryption_title = Label(self, text='Account Settings', font=('Arial', 14), bg=grey)
        encryption_title.grid(column=0, row=1, columnspan=3, pady=(0, 40))

        query = 'SELECT face_rec_enabled FROM Logins WHERE id = "%s";'
        self.master.cursor.execute(query)
        result = self.master.cursor.fetchone()

        if result is not None:
            if result[0] == 1:
                self.face_rec_enabled.set('Enabled')
                self.change_face_rec_status.set('Disable')

        facerec_label = Label(self, text='Face Recognition: ', font=('Arial', 11), bg=grey)
        facerec_label.grid(column=0, row=2)
        self.facerec_status_label = Label(self, textvariable=self.face_rec_enabled, font=('Arial', 11), bg=grey,
                                          fg='#ba0000')
        self.facerec_status_label.grid(column=1, row=2, padx=20)

        facerec_change_button = Button(self, command=lambda status=self.face_rec_enabled: self.config_face_rec(status),
                                       textvariable=self.change_face_rec_status, font=('Arial', 10), bg=grey)
        facerec_change_button.grid(column=2, row=2, padx=20)

    def config_face_rec(self, status):
        if status.get() == 'Enabled':
            self.disable_face_rec()
        else:
            self.enable_face_rec()

    def enable_face_rec(self):
        result = messagebox.askokcancel('Enable Face Recognition',
                                        'Face Recognition will be used to identify you when you attempt to sign in.\n\n'
                                        'To enable this feature, you must upload 10 images of your face. \n\n')
        if result:
            self.master.switch_frame(EnableFaceRecognitionPage)
            return

        # self.face_rec_enabled.set('Enabled')
        # self.facerec_status_label.configure(fg='green')
        # self.change_face_rec_status.set('Disable')

    def disable_face_rec(self):
        self.face_rec_enabled.set('Disabled')
        self.facerec_status_label.configure(fg='#ba0000')
        self.change_face_rec_status.set('Enable')


class EnableFaceRecognitionPage(Frame):
    def __init__(self, master):
        grey = master.grey
        Frame.__init__(self, master, bg=grey)
        self.num_of_files = IntVar(self, 0)
        self.num_of_uploaded_files_str = StringVar(self, f'Number of Uploaded Files: {self.num_of_files.get()}')
        self.uploaded_files = []
        self.labels = []

        title_label = Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        title_label.grid(column=0, row=0, pady=40, ipadx=10, ipady=5, columnspan=6)

        instructions = 'Face Recognition will be used to identify you when you attempt to sign in.\n\n'
        instructions += 'To enable this feature, you must upload 10 images of your face so we know what you look like.'
        instructions = StringVar(self, instructions)

        instructions_label = Label(self, textvariable=instructions, font=('Arial', 11), bg=grey)
        instructions_label.grid(column=0, row=1, columnspan=6)

        self.upload_images_button = Button(self, text='Upload Images', font=('Arial', 11), bg='#A9D7FF',
                                           command=self.upload_images)
        self.upload_images_button.grid(column=0, row=2, pady=20, columnspan=5)

        cancel_button = Button(self, text='Cancel', command=self.cancel, font=('Arial', 11), bg='#D11A2A')
        cancel_button.grid(column=1, row=2, columnspan=5, pady=20)

        uploaded_files_label = Label(self, textvariable=self.num_of_uploaded_files_str, font=('Arial', 11), bg=grey)
        uploaded_files_label.grid(column=0, row=4, columnspan=6)

        self.train_button = Button(self, text='Confirm', command=self.train, font=('Arial', 11), bg=grey)
        self.train_button.grid(column=0, row=5, pady=20, columnspan=2)
        self.train_button.grid_remove()

        # img = ImageTk.PhotoImage(Image.open('D:/Downloads/unknown.png').resize((200, 200), Image.ANTIALIAS))
        # Label(self, bg=grey, image=img)
        # self.img1.photo=img
        # self.img1.grid(column=0, row=6)

    def upload_images(self):

        filetypes = (
            ('Images', '*.png'),
            ('All files', '*.*')
        )
        self.uploaded_files = []
        self.num_of_files.set(0)

        files = filedialog.askopenfilenames(filetypes=filetypes)

        self.train_button.grid_remove()
        for label in self.labels:
            label.destroy()

        if files is None:
            return

        for i in range(len(files)):
            if files[i] not in self.uploaded_files:

                if len(self.uploaded_files) == 10:
                    self.train_button.grid()
                else:
                    self.num_of_files.set(self.num_of_files.get() + 1)
                    self.num_of_uploaded_files_str.set(f'Number of Uploaded Files: {self.num_of_files.get()}')
                    self.uploaded_files.append(files[i])

        row = 6
        column = 0
        for i in range(len(self.uploaded_files)):
            if i != 0 and i % 5 == 0:
                row += 1
                column = 0

            img = ImageTk.PhotoImage(Image.open(self.uploaded_files[i]).resize((100, 100), Image.ANTIALIAS))
            img_label = Label(self, bg='white', image=img)
            img_label.photo = img
            img_label.grid(column=column, row=row, pady=5, padx=5)
            column += 1
            self.labels.append(img_label)

            if i == 9:
                return

    def train(self):
        self.upload_images_button.configure(state=DISABLED)
        self.train_button.configure(state=DISABLED)
        dir_name = self.master.account.first_name.lower() + '-' + self.master.account.last_name.lower()

        if not os.path.isdir(dir_name):
            os.mkdir(dir_name)

    def cancel(self):
        self.master.switch_frame(SettingsPage)


class Account:
    def __init__(self, id, email, first_name, last_name):
        self.id = id
        self.email = email
        self.first_name = first_name
        self.last_name = last_name


def main():
    root = App()
    root.mainloop()


if __name__ == '__main__':
    main()
