import base64
from Crypto.Cipher import AES
from Crypto.Cipher import Random
from Crypto.Protocol.KDF import PBKDF2
import binascii
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
#variables used
BLOCK_SIZE = 16
pad= lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
file
class Home_Screen:
    def __init__(self,master):
        self.master=master
        self.frame=Frame(self.master)
        encryption_btn=Button(self.frame,text='encryption',bg='green',command=self.encryption,font=10).pack(padx=20,pady=20)
        decryption_btn=Button(self.frame,text='decryption',bg='red',command=self.decryption,font=10).pack(padx=10,pady=10)
        self.frame.pack()
    def encryption(self):
        self.newWindow = Toplevel(self.master)
        self.app = Encrypting(self.newWindow)
    def decryption(self):
        self.newWindow = Toplevel(self.master)
        self.app = Decrypting(self.newWindow)       

class Encrypting:
    def __init__(self,master):
        self.master=master
        a= StringVar()
        b= StringVar()
        self.frame=Frame(self.master,width=200,height=100)
        self.spacetext=Label(self.frame,width=50).pack(padx=20,pady=30)
        self.message=Label(self.frame,text='enter the message to be encrypted').pack()
        self.message_text=Entry(self.frame,textvariable= a).pack()
        self.password=Label(self.frame,text='enter the password').pack()
        self.password_text=Entry(self.frame,textvariable= b).pack()
        self.uploadButton=Button(self.frame,text='UPLOAD',command=Encrypting.fileopener,width=40).pack(padx=10,pady=20)
        self.process_btn=Button(self.frame,text='ENCRYPT',command=Encrypting.process,width=40).pack(padx=10,pady=20)
        self.spacetext=Label(self.frame,width=50).pack(padx=20,pady=30)
        self.frame.pack(fill=None, expand=False)
        
    def fileopener():
        file=filedialog.askopenfile()
        
    def process():
        if_control=0
        message=a.get()
        password=b.get()
        
        messagebox.showinfo(title='successful',message='file path')
        
class Decrypting:
    def __init__(self,master):
        self.master=master
        b= StringVar()
        self.frame=Frame(self.master,width=200,height=100)
        self.spacetext=Label(self.frame,width=50).pack(padx=20,pady=30)
        self.password=Label(self.frame,text='enter the password').pack()
        self.password_text=Entry(self.frame,textvariable= b).pack()
        self.uploadButton=Button(self.frame,text='upload the video',command=Decrypting.fileopener,width=40).pack(padx=10,pady=20)
        self.process_btn=Button(self.frame,text='DECRYPT',command= Decrypting.process,width=40).pack(padx=10,pady=20)
        self.spacetext=Label(self.frame,width=50).pack(padx=20,pady=30)
        self.frame.pack(fill=None, expand=False)
    def fileopener():
        file=filedialog.askopenfile()
    def process():
        messagebox.showinfo(title='successfully decrypted',message='secret message')

def main(): 
    root = Tk()
    root.title('encryption App')
    root.geometry("200x200+100+100")
    app=Home_Screen(root)
    root.mainloop()

if __name__ == '__main__':
    main()
