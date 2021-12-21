import tkinter as tk

import main_page
from enable_face_recognition_page import EnableFaceRecognitionPage
from tkinter import messagebox


class SettingsPage(tk.Frame):
    def __init__(self, master):
        grey = master.grey
        tk.Frame.__init__(self, master, bg=grey)

        self.face_rec_enabled = tk.StringVar(value='Disabled')
        self.change_face_rec_status = tk.StringVar(value='Enable')

        if self.master.face_rec_enabled:
            self.face_rec_enabled.set(value='Enabled')
            self.change_face_rec_status.set(value='Disable')

        title_label = tk.Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        title_label.grid(column=0, row=0, pady=40, ipadx=10, ipady=5, columnspan=3)

        encryption_title = tk.Label(self, text='Account Settings', font=('Arial', 14), bg=grey)
        encryption_title.grid(column=0, row=1, columnspan=3, pady=(0, 40))

        query = 'SELECT face_rec_enabled FROM Logins WHERE id = "%s";'
        self.master.cursor.execute(query)
        result = self.master.cursor.fetchone()

        if result is not None:
            if result[0] == 1:
                self.face_rec_enabled.set('Enabled')
                self.change_face_rec_status.set('Disable')

        facerec_label = tk.Label(self, text='Face Recognition: ', font=('Arial', 11), bg=grey)
        facerec_label.grid(column=0, row=2)
        self.facerec_status_label = tk.Label(self, textvariable=self.face_rec_enabled, font=('Arial', 11), bg=grey)
        self.facerec_status_label.grid(column=1, row=2, padx=20)

        if self.master.face_rec_enabled:
            self.facerec_status_label.config(fg='green')
        else:
            self.facerec_status_label.config(fg='#ba0000')

        facerec_change_button = tk.Button(self, command=lambda status=self.face_rec_enabled: self.config_face_rec(status),
                                       textvariable=self.change_face_rec_status, font=('Arial', 10), bg=grey)
        facerec_change_button.grid(column=2, row=2, padx=20)

        back_button = tk.Button(self, command=self.go_back, text='Return to Main Page', font=('Arial', 10), bg=grey)
        back_button.grid(column=1, row=3, pady=30)

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

    def go_back(self):
        self.master.switch_frame(main_page.MainPage)

    def disable_face_rec(self):
        result = messagebox.askyesno('Confirmation', 'Are you sure you want to disable Face Recognition?')
        if not result:
            return

        self.face_rec_enabled.set('Disabled')
        self.facerec_status_label.configure(fg='#ba0000')
        self.change_face_rec_status.set('Enable')

        query = 'UPDATE Logins SET face_rec_enabled = 0 WHERE id = "%d"' % self.master.account.id
        self.master.cursor.execute(query)
        self.master.db.commit()

        self.master.face_rec_enabled = False

        self.master.switch_frame(SettingsPage)