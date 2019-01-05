from tkinter import *
import time
import datetime
import math
import random
import base64
import os
from cryptography import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os.path

# above are a list of python libraries that need to be imported in order to run this script; all of these assets come with pytho except for the cryptography pack, which was installed using PyInstaller

# create empty window and define styles for window, including the height and width of the screen
root = Tk()
root.title("Secure Login Screen")
root.geometry("600x450")
root.resizable(False, False)

# centering the window in the center of the users screen
positionRight = int(root.winfo_screenwidth() / 2 - 300) # we put minus 300 because the window is 600 pixels wide, and we need to get the center of the window
positionDown = int(root.winfo_screenheight() / 2 - 300) # we put minus 300 here just because I think it actually looks better than half of the vertical height; that does mean this window isn't centered vertically
root.geometry("+{}+{}".format(positionRight, positionDown))

# functions list for use in the program
# change inputed word into encrypted key for comparison to outside files
def key_generator(word):
    password_provided = word  # This is input in the form of a string
    password = password_provided.encode()  # Convert to type bytes

    # CHANGE THIS WITH EVERY FILE - recommend using a key from os.urandom(16) command, must be of type bytes
    salt = b'\xc5P*\xe0a\xc2\\rr+\x95\x18\x995*\x8c'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(
        kdf.derive(password))  # Can only use kdf once
    return key

# import list of usernames from outside file (name is set)
def make_user_list():
    if os.path.exists("usernames.encrypted"):
        user_file = open("usernames.encrypted", "r")
    else:
        user_file = open("../usernames.encrypted", "r")
    # this is to read the usernames in the file imported
    # turn imported user file as an array of information to be read
    user_list = list(user_file.read().split(','))
    user_file.close() # remember to close the files once imported
    return user_list

# import list of passwords from outside file (name is set)
def make_pass_list():
    if os.path.exists("passwords.encrypted"):
        pass_file = open("passwords.encrypted", "r")
    else:
        pass_file = open("../passwords.encrypted", "r")
    # this is to read the passwords in the file imported
    # turn imported password file as an array of information to be read
    pass_list = list(pass_file.read().split(','))
    pass_file.close() # remember to close the files once imported
    return pass_list

# attempt login while printing steps to both console and window the user is in
def printLogin():
    print("Logging you in...")
    time.sleep(0.3)
    print("Finding Name Input...")
    time.sleep(0.2)
    name = entryName.get()
    # check if name is blank from the gotten variable
    if name != "":
        print("Name Input Found: " + name)
        time.sleep(0.3)
        print("Finding Password Input...")
        time.sleep(0.2)
        password = entryPassword.get()
        # check if password is blank from the gotten variable
        if password != "":
            print("Password Input Found: ")
            print("Varifying Login Status...")
            # encrypt username and password using the key_generator function
            username_key = key_generator(name).decode()
            password_key = key_generator(password).decode()
            # check if encoded username is in the list imported from the username file and if the encrypted password is in the password list
            if username_key in make_user_list() and password_key in make_pass_list():
                # find their position in the imported array
                positionName = make_user_list().index(username_key)
                positionPass = make_pass_list().index(password_key)
                # check if the two positions are equivalent to each other; if so, then the login is successful
                if positionName == positionPass:
                    print("Welcome " + name)
                    # delete failure message if visable and display login success message
                    failureMessage.grid_forget()
                    successMessage.grid(row=3, columnspan=2)
                else:
                    print("We don't recognize that name and password combination... Uh oh.")
                    # delete success message if visable and display login failure message
                    successMessage.grid_forget()
                    failureMessage.grid(row=3, columnspan=2)
            else:
                print("We don't recognize that name and password combination... Uh oh.")
                # delete success message if visable and display login failure message
                successMessage.grid_forget()
                failureMessage.grid(row=3, columnspan=2)
        elif password == "":
            print("No password inpute detected, please try again.")
            # delete success message if visable and display login failure message
            successMessage.grid_forget()
            failureMessage.grid(row=3, columnspan=2)
    elif name == "":
        print("No name inpute detected, please try again.")
        # delete success message if visable and display login failure message
        successMessage.grid_forget()
        failureMessage.grid(row=3, columnspan=2)

# declare that an event has occured when user presses a button
def buttonPressed(event):
    print("Event Detected...")

# get the current date and time to be displayed in a clock
def dateTimeCurrent():
    currentDateTime = datetime.datetime.now()
    # %d get the current date number, %A gets the current day name, %Y gets the current year, and %B gets the current month; all together simply puts the message in proper date format
    currentDate = currentDateTime.strftime("%d")
    currentDay = currentDateTime.strftime("%A")
    currentYear = currentDateTime.strftime("%Y")
    currentMonth = currentDateTime.strftime("%B")
    allTogether = str("{0}, {1} {2}, {3}".format(
        currentDay, currentMonth, currentDate, currentYear))
    return allTogether

# nine frames for placement in window; this is to create a 3x3 grid for placing widgets and organizing the dispaly
frame_topleft = Frame(width=200, height=150)
frame_topcenter = Frame(width=200, height=150)
frame_topright = Frame(width=200, height=150)
frame_left = Frame(width=200, height=150)
frame_center = Frame(width=200, height=150)
frame_right = Frame(width=200, height=150)
frame_bottomleft = Frame(width=200, height=150)
frame_bottomcenter = Frame(width=200, height=150)
frame_bottomright = Frame(width=200, height=150)

# now let's place these frames in the root window in grid formation
frame_topleft.grid(row=0, column=0)
frame_topcenter.grid(row=0, column=1)
frame_topright.grid(row=0, column=2)
frame_left.grid(row=1, column=0)
frame_center.grid(row=1, column=1)
frame_right.grid(row=1, column=2)
frame_bottomleft.grid(row=2, column=0)
frame_bottomcenter.grid(row=2, column=1)
frame_bottomright.grid(row=2, column=2)

# create login Screen widgets for center frame
labelName = Label(frame_center, text="Name", fg="black")
labelPassword = Label(frame_center, text="Password", fg="black")
entryName = Entry(frame_center)
entryPassword = Entry(frame_center, show="*")
# these two messages will be placed by the login fucntion, but were created here because they would be placed in the center frame
failureMessage = Label(frame_center, text="I'm sorry, there was an error.", fg="black")
successMessage = Label(frame_center, text="Awesome, welcome.", fg="black")

# now we place the widgets we just made in the frames; REMEMBER: var.grid(row, column, alignment(N,E,W,S))
labelName.grid(row=0, column=0, sticky=E)
labelPassword.grid(row=1, column=0, sticky=E)
entryName.grid(row=0, column=1, sticky=W)
entryPassword.grid(row=1, column=1, sticky=W)

# create the sign in button, place it, and bind the appropriate functions to it.
login = Button(frame_center, text="Login", fg="black", command=printLogin)
login.bind("<Button-1>", buttonPressed)
login.grid(row=2, columnspan=2)

# time system for the bottom right using the currentDateTime function
labelDate = Label(frame_bottomright, text=dateTimeCurrent(), fg="black")
labelDate.pack()

# keep the window running until closed by the user
root.mainloop()
