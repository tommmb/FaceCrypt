import tkinter as tk
import bcrypt
import re
from tkinter import messagebox
import face_recognition_login
import register_page
from main_page import MainPage
from account import Account

class LoginPage(tk.Frame):
    def __init__(self, master):
        grey = master.grey
        tk.Frame.__init__(self, master, bg=grey)

        title_label = tk.Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        title_label.grid(column=1, row=0, pady=80, ipadx=10, ipady=5)

        email = tk.StringVar()
        email_label = tk.Label(self, text='Email:', bg=grey, font=('Arial', 10))
        email_label.grid(column=0, row=1, pady=10)
        email_field = tk.Entry(self, textvariable=email, width=37, font=('Arial', 12))
        email_field.configure(highlightbackground=grey)
        email_field.grid(column=1, row=1, pady=10)

        password = tk.StringVar()
        password_label = tk.Label(self, text='Password:', bg=grey, font=('Arial', 10))
        password_label.grid(column=0, row=2, pady=5)
        password_field = tk.Entry(self, textvariable=password, show='\u2022', width=37, font=('Arial', 12))
        password_field.grid(column=1, row=2, pady=10)

        login_button = tk.Button(self, text='Sign In', bg='#A9D7FF', font=('Arial', 11),
                              command=lambda email=email_field, password=password_field: self.login(email, password))
        login_button.configure(highlightbackground=grey)
        login_button.grid(column=1, row=3, ipadx=145, pady=20)

        register_label = tk.Label(self, text="Don't have an account?", bg=grey, font=('Arial', 10)) \
            .grid(column=1, row=4, pady=10, columnspan=2)
        register_button = tk.Button(self, text='Register', command=lambda: master.switch_frame(register_page.RegisterPage), width=10,
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

        regex = re.search("^[^@\s]+@[^@\s]+\.[^@\s]+$", email)
        if regex is None:
            messagebox.showwarning('Email Error', 'Please enter a valid email.')
            return

        try:
            email = regex.group(0)
            salt_query = 'SELECT salt FROM Logins WHERE email = "%s" LIMIT 1;' % email
            self.master.cursor.execute(salt_query)
            salt = self.master.cursor.fetchone()[0]

            hashed = bcrypt.hashpw(bytes(password, 'utf-8'), salt.encode('utf-8')).decode('utf-8')
            query = 'SELECT id, face_rec_enabled FROM Logins WHERE email = "%s" AND password = "%s" LIMIT 1;' % (email, hashed)
            self.master.cursor.execute(query)
            res = self.master.cursor.fetchone()
            id = res[0]
            face_rec_enabled = res[1]

            query2 = 'SELECT first_name, last_name FROM Users WHERE user_id="%s"' % id
            self.master.cursor.execute(query2)
            result = self.master.cursor.fetchone()

            if result is None:
                raise Exception

            # successfully logged in

            if face_rec_enabled == 1:
                self.master.face_rec_enabled = True
                self.master.account = Account(id, email, result[0], result[1])
                self.master.switch_frame(face_recognition_login.FaceRecognitionLogin)
                # self.master.switch_frame(MainPage)
            else:
                self.master.account = Account(id, email, result[0], result[1])
                self.master.face_rec_enabled = False
                self.master.switch_frame(MainPage)

        except Exception as a:
            print(a)
            messagebox.showwarning('Sign in Error', 'Incorrect email or password')
