import tkinter
from tkinter import *
from PIL import Image,ImageTk
from cryptography.fernet import Fernet
from tkinter import messagebox
import base64
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
Font=("Verdana",20,"normal")

window = Tk()
window.title("secret notes")




photo =PhotoImage(file="secret3.png")
#photo=Label(image=photo)
#photo.pack()

canvas = Canvas(height=200,width=200)
canvas.create_image(100,100,image=photo)
canvas.pack()


label1=Label(text="enter your title",font=Font)
label1.pack()

entry1=Entry(width=30)
entry1.pack()

label2=Label(text="enter your secret")
label2.pack()

text1=Text(width=30)
text1.pack()

label3=Label(text="enter your master key")
label3.pack()

entry2=Entry()
entry2.pack()

def save_text():
    title = entry1.get()
    message = text1.get(1.0, END)
    master_secret = entry2.get()
    if len(title) == 0 or len(message)==0 or len(master_secret)==0:
        messagebox.showwarning(title="Error!",message="Please enter all info!!")
    else:
        #encryption
        message_encrypted= encode(master_secret,message)
        try:
            with open("mysecret.txt","a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt","w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            entry1.delete(0,END)
            entry2.delete(0,END)
            text1.delete("1.0",END)

def decryptıon():
    message_encrypted=text1.get("1.0",END)
    secret_master = entry2.get()

    if len(message_encrypted)==0 or len(secret_master) ==0:
        messagebox.showwarning(title="Error!!",message="!Please enter all info")

    else:
        try:
            decrypted_message= decode(secret_master,message_encrypted)
            text1.delete("1.0",END)
            text1.insert("1.0",decrypted_message)
        except:
            messagebox.showwarning(title="Error!!",message="Please enter encrypted test")

encrypt_button=Button(text="encrypt & save",command=save_text)
encrypt_button.pack()



decrypt_button=Button(text="Decrypt",command=decryptıon)
decrypt_button.pack()
window.mainloop()