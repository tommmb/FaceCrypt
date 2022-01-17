import tkinter as tk
from mysql import connector
import windows.login_page as login_page
# from login_page import LoginPage

class App(tk.Tk):
    def __init__(self):
        self.grey = '#CDCDCD'
        #self.db = connector.connect(
        #    host="localhost",
        #    user="root",
        #    passwd="root",
        #    database='project'
        #)
        
        self.db = connector.connect(
            host = 'project-db.cozci0btgeyl.eu-west-2.rds.amazonaws.com',
            user = 'root',
            passwd = 'password',
            port = 3306,
            database = 'project'
        )

        self.cursor = self.db.cursor(buffered=True)

        tk.Tk.__init__(self)
        self.geometry('1000x700')
        self.resizable(0, 0)
        self.title('Project Name')
        self.configure(bg=self.grey)
        self._frame = None
        self.file_name = ''
        self.master_text = ''
        self.is_encrypted = False
        self.switch_frame(login_page.LoginPage)
        self.file_in_db = False

    def switch_frame(self, frame_class):
        new_frame = frame_class(self)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.pack()
        
