from tkinter import Tk
from tkinter import Frame
from tkinter import Label
from tkinter import Entry
from tkinter import Button
from tkinter import Text
from tkinter import StringVar
from tkinter import messagebox
from tkinter import filedialog
from tkinter import END
from mysql import connector
from bcrypt import gensalt, hashpw
from re import search
from os.path import basename


class App(Tk):
    def __init__(self):
        self.grey = '#CDCDCD'
        self.db = connector.connect(
            host="localhost",
            user="root",
            passwd="root",
            database='project'
        )

        self.cursor = self.db.cursor()

        Tk.__init__(self)
        self.geometry('900x600')
        self.resizable(0, 0)
        self.title('Project Name')
        self.configure(bg=self.grey)
        self._frame = None
        self.switch_frame(LoginPage)

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

        login_button = Button(self, text='Login', bg='#A9D7FF', font=('Arial', 11),
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
            salt_query = 'SELECT salt FROM Users WHERE email = "%s";' % email
            self.master.cursor.execute(salt_query)
            salt = self.master.cursor.fetchone()[0]

            hashed = hashpw(bytes(password, 'utf-8'), salt.encode('utf-8')).decode('utf-8')
            query = 'SELECT * from Users WHERE email = "%s" AND password = "%s" LIMIT 1;' % (email, hashed)
            self.master.cursor.execute(query)
            result = self.master.cursor.fetchone()

            if result is None:
                raise Exception

            # successfully logged in

            self.master.account = Account(email, result[4], result[5])
            self.master.switch_frame(MainPage)
            messagebox.showinfo('Welcome', f'Welcome, {self.master.account.first_name}')

        except Exception:
            messagebox.showwarning('Login Error', 'Incorrect email or password')
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
        password_label = Label(self, text='Password:', bg=grey, font=('Arial', 10)).grid(column=0, row=2, pady=5, padx=10)
        password_field = Entry(self, textvariable=password, show='\u2022', width=25, font=('Arial', 12))
        password_field.configure(highlightbackground=grey)
        password_field.grid(column=1, row=2, pady=10)

        confirm_password = StringVar()

        confirm_password_label = Label(self, text='Confirm Password:', bg=grey, font=('Arial', 10))
        confirm_password_label.grid(column=0, row=3, pady=10, padx=10)
        confirm_password_field = Entry(self, textvariable=confirm_password, show='•', width=25, font=('Arial', 12))
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
        login_button = Button(self, text='Login', command=lambda: master.switch_frame(LoginPage), font=('Arial', 10), width=6)
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
            query = 'SELECT * FROM Users WHERE email = "%s"' % email
            self.master.cursor.execute(query)
            result = self.master.cursor.fetchone()

            if result is not None:
                messagebox.showwarning('Registration Error', 'A user already exists with that email.')
                return
        except Exception:
            messagebox.showwarning('Registration Error', 'Something went wrong during registration.')
            return

        salt = gensalt(rounds=10).decode('utf-8')
        hashed = hashpw(bytes(password, 'utf-8'), salt.encode('utf-8')).decode('utf-8')

        try:
            query = 'INSERT INTO Users (email, password, salt, first_name, last_name) ' \
                    'VALUES ("%s", "%s", "%s", "%s", "%s");' % (email, hashed, salt, first_name, last_name)
            self.master.cursor.execute(query)
            self.master.db.commit()

            messagebox.showinfo('Success', 'Successfully registered.')
            self.master.switch_frame(LoginPage)

        except Exception:
            messagebox.showwarning('Registration Error', 'Something went wrong during registration.')
            return


class MainPage(Frame):
    def __init__(self, master):
        grey = master.grey
        self.filename = StringVar()
        self.filename.set('None Selected')
        Frame.__init__(self, master, bg=grey)

        title_label = Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        title_label.grid(column=0, row=0, pady=80, ipadx=10, ipady=5, columnspan=4)

        # account = Label(self, text=self.master.account.first_name, font=('Arial', 12), bg=grey)
        # account.grid(column=2, row=0)

        file_label = Label(self, text='Selected File: ', font=('Arial', 12), bg=grey)
        file_label.grid(column=0, row=1)
        file_name = Label(self, textvariable=self.filename, font=('Arial', 12), bg=grey, fg='#7d7d7d')
        file_name.grid(column=1, row=1)
        file_select = Button(self, text='Select File', command=self.select_file, font=('Arial', 10), bg=grey)
        file_select.grid(column=2, row=1)

        self.text = Text(self, height=12)
        self.text.grid(column=0, row=3, columnspan=3)

    def select_file(self):
        filetypes = (
            ('Text Documents', '*.txt'),
            ('Unicode Documents', '*.utf8'),
            ('All files', '*.*')
        )

        file = filedialog.askopenfile(filetypes=filetypes)
        if file is None:
            return

        try:
            text = file.readlines()
        except Exception:
            messagebox.showwarning('File Error', 'The selected file cannot be opened.')
            return

        self.text.delete(1.0, END)
        self.text.insert(1.0, ''.join(text))
        self.filename.set(basename(file.name))


class Account:
    def __init__(self, email, first_name, last_name):
        self.email = email
        self.first_name = first_name
        self.last_name = last_name


def main():
    db = connector.connect(
        host="localhost",
        user="root",
        passwd="root",
        database='project'
    )

    root = App()
    root.mainloop()


if __name__ == '__main__':
    main()
