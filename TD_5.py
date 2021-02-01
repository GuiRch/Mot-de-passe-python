# -*- coding: utf-8 -*-
"""
Created on Sun Dec  6 22:14:23 2020

@author: guill
"""

import bcrypt
import os
from miscreant.aes.siv import SIV # the miscreant librairy provides the AES-SIV construction
import tkinter
from tkinter import * #We use tkinter to create a user interface
from functools import partial
import sqlite3



#%% Add user interface with Tkinter

def validateLogin(username, password):
    user=[]
    user.append([username.get(),password.get()])
    tkWindow.destroy()
    return(user)

#window
tkWindow = Tk()  
tkWindow.geometry('400x150')  
tkWindow.title('Add User')

#username label and text entry box
usernameLabel = Label(tkWindow, text="User Name").grid(row=0, column=0)
username = StringVar()
usernameEntry = Entry(tkWindow, textvariable=username).grid(row=0, column=1)  

#password label and password entry box
passwordLabel = Label(tkWindow,text="Password").grid(row=1, column=0)  
password = StringVar()
passwordEntry = Entry(tkWindow, textvariable=password, show='*').grid(row=1, column=1)  

validateLogin = partial(validateLogin, username, password)

#login button
loginButton = Button(tkWindow, text="Add User", command=validateLogin).grid(row=4, column=0)  

tkWindow.mainloop()

username = username.get() # get the input of the username
print (username)
password = password.get() # get the input of the password
password = password.encode('utf-8') #need a byte type for the password
print(password)

#%% Hash password 

# Here we are using bcrypt instead of Tink 
# bcrypt is a popular library to hash passwords 

# The more secure way to store passwords is to create a salt for each user
# We need a One-Way function quite slow to compute


# bcrypt is based on the Blowfish algorithm and take 100 ms to compute
# It is also possible tu use the time library to make this even slowler 
# The function bcrypt.hashpw create a salt for each hashed password 
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print(hashed)

print(bcrypt.checkpw(password, hashed))

#%% Encrypt the hash in AES-SIV mode

def encryption_machine(msg):
    encrypt=[]
    
    key = SIV.generate_key()
    siv = SIV(key)
    nonce = os.urandom(16) # create a random nonce 
    ciphertext = siv.seal(msg, [nonce]) # msg is in byte 
    
    encrypt.append(ciphertext)
    encrypt.append(nonce)
    encrypt.append(key)
    return encrypt # we create a list with the nonce, the key and the ciphertext to be able to decrypt it later

print(encryption_machine(hashed))

def decryption_machine(encrypt):
    siv = SIV(encrypt[2])
    plaintext = siv.open(encrypt[0], [encrypt[1]])
    return plaintext

#print(decryption_machine(encryption_machine(hashed)))

#%% Store in the data base 

def save_to_database(encrypt):
    database = open("database.txt", "a")
    for elem in encrypt:
        elem = str(elem)
        database.write(elem + " ")
    database.write("\n")
    database.close()

database = open("database.txt", "a")
database.write(username + " ")  
database.close()
save_to_database(encryption_machine(hashed)) 
# This script write on a txt file but this is not the one I use to check passwords
# This txt file is not nescessary, and could be removed, it just allows us to see what is writtent on the database
# Otherwise it is possible to see what is on the db file with DB browser for SQlite

# We open the connection with the database
conn = sqlite3.connect('database.db')
cur = conn.cursor()
#req = " CREATE TABLE users( id integer primary key autoincrement, username TEXT, ciphertext TINYBLOB, nonce TINYBLOB, key TINYBLOB ) "
# This way of entering variable (with ?), is more secure
# Indeed it prevent us from SQL injection attack on the database

# With SQL we can enter on the database bytes variable directly,
# wich is much more practicle than using a txt or csv file

#cur.execute(req) # once the database is created we don't need the req anymore
conn.commit()
conn.close()

# We use SQlite and so SQL to handle the database
# The following function save the encrypted hash of the password and the user name 
# on a SQL databse
def save_sql(username,encrypt):
    ciphertext = encrypt[0]
    nonce = encrypt[1]
    key = encrypt[2]
    
    data = (username, ciphertext, nonce, key)
    
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute(" INSERT INTO users (username, ciphertext, nonce, key) VALUES ( ?, ?, ?, ?) ",data)
    # the secure way to enter the variable
    conn.commit()
    conn.close()
    
save_sql(username,encryption_machine(hashed))

#%% Catch user by username 

# The following function catch users by their name from the SQL database
def get_user_sql(username):
    encrypt = []
    username = (username,)
    
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute(" SELECT ciphertext, nonce, key FROM users WHERE username = ? ",username )
    encrypt = cur.fetchone()
    

    conn.commit()
    conn.close()
    
    return(encrypt) #returns a list, with the encrypted hash, the nonce and the key


encrypt = []
encrypt.append(get_user_sql(username)[0])
encrypt.append(get_user_sql(username)[1])
encrypt.append(get_user_sql(username)[2])

#%% Decrypt the Hash

decrypt_hash = decryption_machine(encrypt) # we use the decryption function created before, 
                                            # in order to decrypt the information get in the database before
print(decrypt_hash)

#%% Check password 

def check_password(password,hashed):
    if bcrypt.checkpw(password, hashed): # bcrypt library provides us this function to check a password and it's hash 
        return(" Good Password ")
    else:
        return(" Wrong password ")
    
print(check_password(b"guillaume",decrypt_hash))
#%% Login interface to check passwords

#window
login_Window = Tk()  
login_Window.geometry('400x150')  
login_Window.title('Check User')

#username label and text entry box
usernameLabel = Label(login_Window, text="User Name").grid(row=0, column=0)
username_input = StringVar()
usernameEntry = Entry(login_Window, textvariable=username_input).grid(row=0, column=1)  

#password label and password entry box
passwordLabel = Label(login_Window,text="Password").grid(row=1, column=0)  
password_input = StringVar()
passwordEntry = Entry(login_Window, textvariable=password_input, show='*').grid(row=1, column=1)  

#checkLogin = partial(checkLogin, username, password)

#login button
#validateButton = Button(login_Window, text="OK").grid(row=4, column=0)  

login_Window.mainloop()

password_input = password_input.get()
password_input = password_input.encode('utf-8')

username_input = username_input.get()


user = get_user_sql(username_input)

hashed_password = decryption_machine(user)

res = check_password(password_input, hashed_password)

message_Window = Tk()  
message_Window.geometry('400x150')  
message_Window.title('Check User')

checkButton = Button(message_Window, text="Check password", command=tkinter.messagebox.showinfo(title="Check users", message = res)).grid(row=4, column=0)


