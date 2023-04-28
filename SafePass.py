import hashlib
import sqlite3
import customtkinter
from functools import partial
from tkinter import *
from tkinter import simpledialog
from tkinter import ttk

customtkinter.set_appearance_mode("light")
customtkinter.set_default_color_theme("blue")

# #App Frame
# app = customtkinter.CTk()
# app.geometry("320x250")
# app.title("SafePass")

# #Adding UI elements
# title = customtkinter.CTkLabel(app, text="Enter Your Master Password")
# title.pack(padx=10, pady=70)

# #Run App
# app.mainloop()

from passgen import passGenerator

# Database Code (you can rename your database file to something less obvious)
with sqlite3.connect("safepass.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
platform TEXT NOT NULL,
account TEXT NOT NULL,
password TEXT NOT NULL);
""")

# Create PopUp


def popUp(text):
    answer = simpledialog.askstring("input string", text)

    return answer

# Initiate Window

window = customtkinter.CTk()
window.geometry("320x250")
window.title("SafePass")

# window = Tk()
# window.update()

# window.title("SafePass")


def hashPassword(input):
    hash1 = hashlib.md5(input)
    hash1 = hash1.hexdigest()

    return hash1

#   Set up master password screen #######################################


def firstTimeScreen():
    window.geometry("300x150")

    title = customtkinter.CTkLabel(window, text="Create Master Password")
    title.pack(padx=10, pady=70)

    # lbl = Label(window, text="Create Master Password")
    # lbl.config(anchor=CENTER)
    # lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    title1 = customtkinter.CTkLabel(window, text="Re-enter Master Password")
    # title.pack(padx=10, pady=80)
    # title1.config(anchor=CENTER)
    title1.pack()

    txt1 = customtkinter.CTkEntry(window, width=20, show="*")
    txt1.pack()

    def savePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))

            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?) """
            cursor.execute(insert_password, [hashedPassword])
            db.commit()
            vaultScreen()

        else:
            title.config(text="Passwords dosen't match")

    btn = customtkinter.CTkButton(window, text="Save", command=savePassword)
    btn.pack(pady=0)

#   Login screen #######################################


def loginScreen():
    window.geometry("300x150")

    titlel = customtkinter.CTkLabel(window, text="Enter Master Password")
    # title1.pack(padx=10, pady=70)
    # titlel.config(anchor=CENTER)
    titlel.pack()

    txt = customtkinter.CTkEntry(window, width=170, show="*")
    txt.pack()
    txt.focus()

    # title1 = customtkinter.CTkLabel(window)
    # title1.pack()

    def getMasterPassword():
        checkhashedpassword = hashPassword(txt.get().encode("utf-8"))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [checkhashedpassword])

        return cursor.fetchall()

    def checkPassword():
        password = getMasterPassword()

        if password:
            vaultScreen()

        else:
            txt.delete(0, 'end')
            # titlel = customtkinter.CTkLabel(window, text="Wrong Password")
            # lbl1.config(text="Wrong Password")

    btn = customtkinter.CTkButton(window, text="Submit", command=checkPassword)
    btn.pack(pady=20)

#   Vault functionalities #######################################


def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Platform"
        text2 = "Type of Account"
        text3 = "Password"

        platform = popUp(text1)
        account = popUp(text2)
        password = popUp(text3)

        insert_fields = """INSERT INTO vault(platform, account, password)
        VALUES(?, ?, ?)"""

        cursor.execute(insert_fields, (platform, account, password))
        db.commit()
        vaultScreen()

    def updateEntry(input):
        update = "Type new password"
        password = popUp(update)

        cursor.execute("UPDATE vault SET password = ? WHERE id = ?", (password, input,))
        db.commit()
        vaultScreen()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        vaultScreen()

    def copyAcc(input):
        window.clipboard_clear()
        window.clipboard_append(input)

    def copyPass(input):
        window.clipboard_clear()
        window.clipboard_append(input)

#   Window layout #######################################

    window.geometry("720x550")
    main_frame = customtkinter.CTkFrame(window)
    main_frame.pack(fill=BOTH, expand=True)

    my_canvas = customtkinter.CTkCanvas(main_frame)
    my_canvas.pack(side=LEFT, fill=BOTH, expand=True)

    my_scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
    my_scrollbar.pack(side=RIGHT, fill=Y)

    my_canvas.configure(yscrollcommand=my_scrollbar.set)
    my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))

    second_frame = customtkinter.CTkFrame(my_canvas)

    my_canvas.create_window((0, 0), window=second_frame, anchor="nw")

    lbl = customtkinter.CTkLabel(second_frame, text)
    lbl.grid(column=2)

    btn2 = customtkinter.CTkButton(second_frame, text="Generate Password", command=passGenerator)
    btn2.grid(column=2, pady=10)

    btn = customtkinter.CTkButton(second_frame, text="Store New", command=addEntry)
    btn.grid(column=4, pady=10)

    lbl = customtkinter.CTkLabel(second_frame, text="Platform")
    lbl.grid(row=2, column=0, padx=40)
    lbl = customtkinter.CTkLabel(second_frame, text="Type of Account")
    lbl.grid(row=2, column=1, padx=40)
    lbl = customtkinter.CTkLabel(second_frame, text="Password")
    lbl.grid(row=2, column=2, padx=50)

    cursor.execute("SELECT * FROM vault")

#   Buttons Layout #######################################

    if cursor.fetchall() is not None:
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            lbl1 = customtkinter.CTkLabel(second_frame, text=(array[i][1]))
            lbl1.grid(column=0, row=i + 3)
            lbl2 = customtkinter.CTkLabel(second_frame, text=(array[i][2]))
            lbl2.grid(column=1, row=i + 3)
            lbl3 = customtkinter.CTkLabel(second_frame, text=(array[i][3]))
            lbl3.grid(column=2, row=i + 3)
            btn2 = customtkinter.CTkButton(second_frame, text="Copy Acc", command=partial(copyAcc, array[i][2]))
            btn2.grid(column=3, row=i + 3, pady=10)
            btn3 = customtkinter.CTkButton(second_frame, text="Copy Pass", command=partial(copyPass, array[i][3]))
            btn3.grid(column=4, row=i + 3, pady=10)
            btn1 = customtkinter.CTkButton(second_frame, text="Update", command=partial(updateEntry, array[i][0]))
            btn1.grid(column=5, row=i + 3, pady=10)
            btn = customtkinter.CTkButton(second_frame, text="Delete", command=partial(removeEntry, array[i][0]))
            btn.grid(column=6, row=i + 3, pady=10)

            i = i + 1

            cursor.execute("SELECT * FROM vault")
            if len(cursor.fetchall()) <= i:
                break


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstTimeScreen()
window.mainloop()
