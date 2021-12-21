import tkinter as tk
import cv2
from PIL import ImageTk, Image
import windows.login_page as login_page
import cv2.cv2 as cv2
import cv2.data as data
import pickle
import os

import windows.main_page as main_page


class FaceRecognitionLogin(tk.Frame):
    def __init__(self, master):
        grey = master.grey
        tk.Frame.__init__(self, master, bg=grey)

        self.face_cascade = cv2.CascadeClassifier(data.haarcascades + 'haarcascade_frontalface_alt2.xml')
        self.recognizer = cv2.face.LBPHFaceRecognizer_create()
        self.recognizer.read('trainer.yml')
        self.labels = {}
        with open(os.path.abspath('labels.pickle'), 'rb') as f:
            og_labels = pickle.load(f)
            self.labels = {value: key for key, value in og_labels.items()}

        title_label = tk.Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        title_label.grid(column=0, row=0, pady=20, ipadx=10, ipady=5)

        self.display_video = tk.Label(self)
        self.display_video.grid(column=0, row=3)

        face_rec_label = tk.Label(self, text='Look into the camera', font=('Arial', 12), bg=grey)
        face_rec_label.grid(column=0, row=1)

        cancel_button = tk.Button(self, text='Cancel', command=self.cancel, font=('Arial', 11), bg=grey)
        cancel_button.grid(column=0, row=2, pady=10)

        self.cap = cv2.VideoCapture(0)
        self.video_stream()

        self.i=0

    def video_stream(self):
        ret, frame = self.cap.read()
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = self.face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4)

        for (x, y, w, h) in faces:
            roi_gray = gray[y: y + h, x: x + h]
            roi_color = frame[y: y + h, x: x + h]

            id_, conf = self.recognizer.predict(roi_gray)
            name = self.labels[id_]

            if conf >= 60:
                font = cv2.FONT_HERSHEY_SIMPLEX
                color = (0, 0, 0)
                stroke = 2
                cv2.putText(frame, 'Unknown', (x, y), font, 1, color, stroke, cv2.LINE_AA)
            else:
                if self.i >= 10:
                    self.master.switch_frame(main_page.MainPage)
                    return
                font = cv2.FONT_HERSHEY_SIMPLEX
                color = (255, 255, 255)
                stroke = 2
                cv2.putText(frame, name, (x, y), font, 1, color, stroke, cv2.LINE_AA)
                if str(name) == str(self.master.account.first_name.lower() + '-' + self.master.account.last_name.lower() + '-' + str(self.master.account.id)):
                    self.i += 1

            color = (255, 0, 0)
            stroke = 2
            end_cord_x = x + w
            end_cord_y = y + h
            cv2.rectangle(frame, (x, y), (end_cord_x, end_cord_y), color, stroke)

        cv2img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGBA)
        img = Image.fromarray(cv2img)
        imgtk = ImageTk.PhotoImage(image=img)

        self.display_video.imgtk = imgtk
        self.display_video.configure(image=imgtk)
        self.display_video.after(33, self.video_stream)

    def cancel(self):
        self.master.switch_frame(login_page.LoginPage)