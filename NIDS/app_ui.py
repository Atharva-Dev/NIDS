import tkinter
from tkinter import *
import nids

win = Tk()
win.title('NIDS')
windowWidth = win.winfo_reqwidth()
windowHeight = win.winfo_reqheight()
print("Width",windowWidth,"Height",windowHeight)

positionRight = int(win.winfo_screenwidth()/2 - windowWidth/2)
positionDown = int(win.winfo_screenheight()/2 - windowHeight/2)


win.geometry("+{}+{}".format(positionRight, positionDown))
win.mainloop()