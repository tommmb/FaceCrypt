import tkinter as tk
import settings_page
import os
from tkinter import filedialog
from PIL import Image, ImageTk
import cv2
import cv2.data as data
import pickle
import numpy as np


class EnableFaceRecognitionPage(tk.Frame):
    def __init__(self, master):
        grey = master.grey
        tk.Frame.__init__(self, master, bg=grey)
        self.num_of_files = tk.IntVar(self, 0)
        self.num_of_uploaded_files_str = tk.StringVar(self, f'Number of Uploaded Files: {self.num_of_files.get()}')
        self.uploaded_files = []
        self.original_images = []
        self.labels = []

        title_label = tk.Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        title_label.grid(column=0, row=0, pady=40, ipadx=10, ipady=5, columnspan=6)

        instructions = 'Face Recognition will be used to identify you when you attempt to sign in.\n\n'
        instructions += 'To enable this feature, you must upload 10 images of your face so we know what you look like.'
        instructions = tk.StringVar(self, instructions)

        instructions_label = tk.Label(self, textvariable=instructions, font=('Arial', 11), bg=grey)
        instructions_label.grid(column=0, row=1, columnspan=6)

        self.upload_images_button = tk.Button(self, text='Upload Images', font=('Arial', 11), bg='#A9D7FF',
                                           command=self.upload_images)
        self.upload_images_button.grid(column=1, row=2, pady=20, columnspan=3)

        self.cancel_button = tk.Button(self, text='Cancel', command=self.cancel, font=('Arial', 11), bg='#D11A2A')
        self.cancel_button.grid(column=3, row=2, columnspan=3, pady=20)

        uploaded_files_label = tk.Label(self, textvariable=self.num_of_uploaded_files_str, font=('Arial', 11), bg=grey)
        uploaded_files_label.grid(column=0, row=4, columnspan=6)

        self.train_button = tk.Button(self, text='Confirm', command=self.train, font=('Arial', 11), bg=grey)
        self.train_button.grid(column=0, row=5, pady=20, columnspan=6)
        self.train_button.grid_remove()

        # img = ImageTk.PhotoImage(Image.open('D:/Downloads/unknown.png').resize((200, 200), Image.ANTIALIAS))
        # tk.Label(self, bg=grey, image=img)
        # self.img1.photo=img
        # self.img1.grid(column=0, row=6)

    def upload_images(self):

        filetypes = (
            ('PNG Images', '*.png'),
            ('JPG Images', '*.jpg'),
            ('All files', '*.*')
        )
        self.uploaded_files = []
        self.num_of_files.set(0)

        files = filedialog.askopenfilenames(filetypes=filetypes)
        print(files)

        self.train_button.grid_remove()
        for label in self.labels:
            label.destroy()

        if files is None:
            return

        for i in range(len(files)):
            if files[i] not in self.uploaded_files:
                # if len(self.uploaded_files) == 10:
                #     self.train_button.grid()
                # else:
                self.num_of_files.set(self.num_of_files.get() + 1)
                self.num_of_uploaded_files_str.set(f'Number of Uploaded Files: {self.num_of_files.get()}')
                self.uploaded_files.append(files[i])

        # print(len(self.uploaded_files))
        if len(self.uploaded_files) == 10:
            self.train_button.grid()

        row = 6
        column = 0
        for i in range(len(self.uploaded_files)):
            if i != 0 and i % 5 == 0:
                row += 1
                column = 0

            img = ImageTk.PhotoImage(Image.open(self.uploaded_files[i]).resize((100, 100), Image.ANTIALIAS))
            original = Image.open(self.uploaded_files[i])
            self.original_images.append(original)
            img_label = tk.Label(self, bg='white', image=img)
            img_label.photo = img
            img_label.grid(column=column, row=row, pady=5, padx=5)
            column += 1
            self.labels.append(img_label)

            if i == 9:
                return

    def train(self):
        self.upload_images_button.configure(state=tk.DISABLED)
        self.train_button.configure(state=tk.DISABLED)
        self.cancel_button.configure(state=tk.DISABLED)
        label = self.master.account.first_name.lower() + '-' + self.master.account.last_name.lower() + '-' + str(self.master.account.id)
        dir_name = os.getcwd() + f'\\faces\\{label}'
        image_dir = os.getcwd() + f'\\faces'

        if not os.path.isdir(dir_name):
            os.mkdir(dir_name)

        num_of_existing_images = len([name for name in os.listdir(dir_name) if os.path.isfile(name)])

        for i in range(len(self.original_images)):
            self.original_images[i].save(f'{dir_name}\\image-{i}.png')

        face_cascade = cv2.CascadeClassifier(data.haarcascades + 'haarcascade_frontalface_alt2.xml')
        recognizer = cv2.face.LBPHFaceRecognizer_create()

        current_id = 0
        label_ids = {}
        x_train = []  # training data
        y_labels = []  # known values

        for root, dirs, files in os.walk(image_dir):
            for file in files:
                if file.endswith('png'):
                    path = os.path.join(root, file)
                    label = os.path.basename(root).replace(' ', '-').lower()
                    # print(label, path)
                    if not label in label_ids:
                        label_ids[label] = current_id
                        current_id += 1

                    id_ = label_ids[label]
                    pil_image = Image.open(path).convert('L')  # converts to gray sccale
                    size = (550, 550)
                    final_image = pil_image.resize(size, Image.ANTIALIAS)
                    image_array = np.array(final_image, 'uint8')
                    faces = face_cascade.detectMultiScale(image_array, scaleFactor=1.5, minNeighbors=4)

                    for (x, y, w, h) in faces:
                        roi = image_array[y: y + h, x: x + w]
                        x_train.append(roi)
                        y_labels.append(id_)

        with open('labels.pickle', 'wb') as f:
            pickle.dump(label_ids, f)

        recognizer.train(x_train, np.array(y_labels))
        recognizer.save('trainer.yml')

        query = 'UPDATE Logins SET face_rec_enabled = 1 WHERE id = "%d"' % self.master.account.id
        self.master.cursor.execute(query)
        self.master.db.commit()
        self.master.face_rec_enabled = True

        self.master.switch_frame(settings_page.SettingsPage)




    def cancel(self):
        self.master.switch_frame(settings_page.SettingsPage)
