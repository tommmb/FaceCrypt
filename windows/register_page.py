import tkinter as tk
import bcrypt
import re
# from login_page import LoginPage
import windows.login_page as login_page
from tkinter import messagebox


class RegisterPage(tk.Frame):
    def __init__(self, master):
        grey = master.grey
        tk.Frame.__init__(self, master, bg=grey)

        title_label = tk.Label(self, text='FaceCrypt', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        title_label.grid(column=0, row=0, pady=80, ipadx=10, ipady=5, columnspan=4)

        email = tk.StringVar()
        email_label = tk.Label(self, text='Email:', bg=grey, font=('Arial', 10)).grid(column=0, row=1, pady=10, padx=10)
        email_field = tk.Entry(self, textvariable=email, width=25, font=('Arial', 12))
        email_field.configure(highlightbackground=grey)
        email_field.grid(column=1, row=1, pady=10)

        password = tk.StringVar()
        password_label = tk.Label(self, text='Password:', bg=grey, font=('Arial', 10)).grid(column=0, row=2, pady=5,
                                                                                         padx=10)
        password_field = tk.Entry(self, textvariable=password, show='\u2022', width=25, font=('Arial', 12))
        password_field.configure(highlightbackground=grey)
        password_field.grid(column=1, row=2, pady=10)

        confirm_password = tk.StringVar()

        confirm_password_label = tk.Label(self, text='Confirm Password:', bg=grey, font=('Arial', 10))
        confirm_password_label.grid(column=0, row=3, pady=10, padx=10)
        confirm_password_field = tk.Entry(self, textvariable=confirm_password, show='\u2022', width=25, font=('Arial', 12))
        confirm_password_field.configure(highlightbackground=grey)
        confirm_password_field.grid(column=1, row=3, pady=10)

        first_name = tk.StringVar()
        first_name_label = tk.Label(self, text='First Name:', bg=grey, font=('Arial', 10))
        first_name_label.grid(column=2, row=1, padx=20)
        first_name_field = tk.Entry(self, textvariable=first_name, width=25, font=('Arial', 12))
        first_name_field.configure(highlightbackground=grey)
        first_name_field.grid(column=3, row=1, padx=5, pady=10)

        last_name = tk.StringVar()
        last_name_label = tk.Label(self, text='Last Name:', bg=grey, font=('Arial', 10))
        last_name_label.grid(column=2, row=2, padx=20)
        last_name_field = tk.Entry(self, textvariable=last_name, width=25, font=('Arial', 12))
        last_name_field.configure(highlightbackground=grey)
        last_name_field.grid(column=3, row=2, padx=5, pady=10)

        register_button = tk.Button(self, text='Register', bg='#A9D7FF', width=30, font=('Arial', 11),
                                 command=lambda _email=email_field, _password=password_field,
                                                _confirm_password=confirm_password_field, _first_name=first_name_field,
                                                _last_name=last_name_field:
                                 self.register(_email, _password, _confirm_password, _first_name, _last_name))
        register_button.configure(highlightbackground=grey)
        register_button.grid(column=0, row=4, columnspan=4, pady=20)

        login_label = tk.Label(self, text="Already have an account?", bg=grey, font=('Arial', 10))
        login_label.grid(column=0, row=5, pady=5, columnspan=4)
        login_button = tk.Button(self, text='Sign In', command=lambda: master.switch_frame(login_page.LoginPage), font=('Arial', 10),
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

        regex = re.search("^[^@\s]+@[^@\s]+\.[^@\s]+$", email)
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

        salt = bcrypt.gensalt(rounds=10).decode('utf-8')
        hashed = bcrypt.hashpw(bytes(password, 'utf-8'), salt.encode('utf-8')).decode('utf-8')

        try:
            query = 'INSERT INTO Logins (email, password, salt) ' \
                    'VALUES ("%s", "%s", "%s");' % (email, hashed, salt)
            self.master.cursor.execute(query)

            query2 = 'INSERT INTO Users(user_id, first_name, last_name, access_level) ' \
                     'VALUES (LAST_INSERT_ID(), "%s", "%s", "%s")' % (first_name, last_name, 'NORMAL')
            self.master.cursor.execute(query2)
            self.master.db.commit()

            messagebox.showinfo('Success', 'Successfully registered.')
            self.master.switch_frame(login_page.LoginPage)

        except Exception as e:
            print(e)
            messagebox.showwarning('Registration Error', 'Something went wrong during registration.')
            return
