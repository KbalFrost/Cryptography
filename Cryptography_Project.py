import codecs
import hashlib
import customtkinter
import random
import math
import PIL
from PIL import Image
from tkinter import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode



class Home:
    def __init__(self, root):
        root.title("Home")
        root.after(0, lambda:root.state('zoomed'))
        
        image = PIL.Image.open("crypto.png")
        background_image = customtkinter.CTkImage(image, size=(1515, 500))

        titleFrame = customtkinter.CTkFrame(master=root, width=1515, height=250)
        titleFrame.grid(row=0, column=0, columnspan=10, padx=10, pady=10)
        title = customtkinter.CTkLabel(master=titleFrame, text="Cryptography Project\n(Encryption Algorithms)", font=('Arial',42,'bold'), image=background_image)
        title.place(relx=0,rely=0,relwidth=1,relheight=1)

        CAESARbtn = customtkinter.CTkButton(master=root, text="Substitution Cipher\n(Caesar)", width=300, height=100, font=('Arial',30,'bold'), command=self.CAESAR_screen)
        CAESARbtn.grid(row=1, column=2, columnspan=3, pady=25)
        COLUMNARbtn = customtkinter.CTkButton(master=root, text="Transposition Cipher\n(Columnar)", width=300, height=100, font=('Arial',30,'bold'), command=self.COLUMNAR_screen)
        COLUMNARbtn.grid(row=1, column=5, columnspan=3, pady=25)
        AESbtn = customtkinter.CTkButton(master=root, text="Symmetric Key\n(AES)", width=300, height=100, font=('Arial',30,'bold'), command=self.AES_screen)
        AESbtn.grid(row=2, column=1, columnspan=2, pady=25)
        RSAbtn = customtkinter.CTkButton(master=root, text="Asymmetric Key\n(RSA)", width=300, height=100, font=('Arial',30,'bold'), command=self.RSA_screen)
        RSAbtn.grid(row=2, column=4, columnspan=2, pady=25)
        SHAbtn = customtkinter.CTkButton(master=root, text="Hash Function\n(SHA256)", width=300, height=100, font=('Arial',30,'bold'), command=self.SHA_screen)
        SHAbtn.grid(row=2, column=7, columnspan=2, pady=25)

        footerFrame = customtkinter.CTkFrame(master=root, width=1515, height=250)
        footerFrame.grid(row=3, column=0, columnspan=10, padx=10, pady=10)
        footer = customtkinter.CTkLabel(master=footerFrame, text="", image=background_image)
        footer.place(relx=0,rely=0,relwidth=1,relheight=1)

    def main_window(self):
        root.after(0, lambda:root.state('zoomed'))
        self.screen.withdraw()

    def CAESAR_screen(self):
        def encrypt():
            enCipherText.delete("0.0", "1.end")
            pattern = int(patternText.get())
            plaintext = enPlainText.get("0.0", "1.end")
            ciphertext = ""

            for i in range(len(plaintext)):
                ch = plaintext[i]
                
                if ch==" ":
                    ciphertext+=" "
                elif (ch.isupper()):
                    ciphertext += chr((ord(ch) + pattern-65) % 26 + 65)
                else:
                    ciphertext += chr((ord(ch) + pattern-97) % 26 + 97)

            enCipherText.insert("0.0", ciphertext)

        def decrypt():
            dePlainText.delete("0.0", "1.end")
            pattern = int(patternText.get())
            ciphertext = deCipherText.get("0.0", "1.end")
            plaintext = ""

            lowLetters="abcdefghijklmnopqrstuvwxyz"
            upLetters="ABCDEFGHIJKLMNOPQRSTUVWXYZ"

            for ch in ciphertext:
                if ch== " ":
                    plaintext+=" "
                elif (ch.isupper()):
                    if ch in upLetters:
                        position = upLetters.find(ch)
                        new_pos = (position - pattern) % 26
                        new_char = upLetters[new_pos]
                        plaintext += new_char
                    else:
                        plaintext += ch
                else:
                    if ch in lowLetters:
                        position = lowLetters.find(ch)
                        new_pos = (position - pattern) % 26
                        new_char = lowLetters[new_pos]
                        plaintext += new_char
                    else:
                        plaintext += ch                    

            dePlainText.insert("0.0", plaintext)

        def capture(*args):
            if pattern.get()!=' ':
                encryptbtn.configure(state='normal')
                decryptbtn.configure(state='normal')

            else:
                encryptbtn.configure(state='disabled')
                decryptbtn.configure(state='disabled')

        root.withdraw()
        self.screen = customtkinter.CTkToplevel(root)
        self.screen.title("CAESAR")
        self.screen.after(0, lambda:self.screen.state('zoomed'))

        pattern = StringVar()
        pattern.trace('w', capture)

        image = PIL.Image.open("caesar.png")
        background_image = customtkinter.CTkImage(image, size=(1515, 150))

        titleFrame = customtkinter.CTkFrame(master=self.screen, width=1500, height=150)
        titleFrame.grid(row=0, column=0, columnspan=4, padx=15, pady=15)
        title = customtkinter.CTkLabel(master=titleFrame, text="Caesar Cipher\n(Substitution)", font=('Arial',40,'bold'), image=background_image)
        title.place(relwidth=1, relheight=1)

        patternLabel = customtkinter.CTkLabel(master=self.screen, text="Shift pattern: ", width=100, font=('Arial',25))
        patternLabel.place(x=650, y=190)
        patternText = customtkinter.CTkEntry(master=self.screen, textvariable=pattern, width=50, font=('Arial',25))
        patternText.place(x=800, y=190)

        encryptionFrame = customtkinter.CTkFrame(master=self.screen, width=740, height=540)
        encryptionFrame.place(x=15, y=250)
        encryptionTitle = customtkinter.CTkLabel(master=encryptionFrame, text="Encryption", font=('Arial',25,'bold'))
        encryptionTitle.place(relwidth=1, y=10)
        PlainTextLabel = customtkinter.CTkLabel(master=encryptionFrame, text="Plaintext: ", width=100, font=('Arial',20))
        PlainTextLabel.place(x=10, y=30)
        enPlainText = customtkinter.CTkTextbox(master=encryptionFrame, width=720, height=190, font=('Arial',25,'bold'))
        enPlainText.place(x=10, y=60)
        CipherTextLabel = customtkinter.CTkLabel(master=encryptionFrame, text="Ciphertext: ", width=100, font=('Arial',20))
        CipherTextLabel.place(x=10, y=300)
        enCipherText = customtkinter.CTkTextbox(master=encryptionFrame, width=720, height=200, font=('Arial',25,'bold'))
        enCipherText.place(x=10, y=330)
        encryptbtn = customtkinter.CTkButton(master=encryptionFrame, text="Encrypt", state=DISABLED, width=720, height=30, font=('Arial',20,'bold'), command=encrypt)
        encryptbtn.place(x=10, y=260)

        decryptionFrame = customtkinter.CTkFrame(master=self.screen, width=740, height=540)
        decryptionFrame.place(x=775, y=250)
        decryptionTitle = customtkinter.CTkLabel(master=decryptionFrame, text="Decryption", font=('Arial',25,'bold'))
        decryptionTitle.place(relwidth=1, y=10)
        CipherTextLabel = customtkinter.CTkLabel(master=decryptionFrame, text="Ciphertext: ", width=100, font=('Arial',20))
        CipherTextLabel.place(x=10, y=30)
        deCipherText = customtkinter.CTkTextbox(master=decryptionFrame, width=720, height=190, font=('Arial',25,'bold'))
        deCipherText.place(x=10, y=60)
        PlainTextLabel = customtkinter.CTkLabel(master=decryptionFrame, text="Plaintext: ", width=100, font=('Arial',20))
        PlainTextLabel.place(x=10, y=300)
        dePlainText = customtkinter.CTkTextbox(master=decryptionFrame, width=720, height=200, font=('Arial',25,'bold'))
        dePlainText.place(x=10, y=330)
        decryptbtn = customtkinter.CTkButton(master=decryptionFrame, text="Decrypt", state=DISABLED, width=720, height=30, font=('Arial',20,'bold'), command=decrypt)
        decryptbtn.place(x=10, y=260)

        backbtn = customtkinter.CTkButton(master=self.screen, text="Back", width=100, height=25, font=('Arial',20,'bold'), command=self.main_window)
        backbtn.place(x=715, y=800)

    def COLUMNAR_screen(self):
        def encrypt():
            enCipherText.delete("0.0", "1.end")
            plaintext = enPlainText.get("0.0", "1.end")
            keyword = keywordText.get()
            ciphertext = ""
        
            k_indx = 0
            msg_len = float(len(plaintext))
            msg_lst = list(plaintext)
            key_lst = sorted(list(keyword))
            col = len(keyword)
            row = int(math.ceil(msg_len / col))
            fill_null = int((row * col) - msg_len)
            msg_lst.extend('_' * fill_null)
            matrix = [msg_lst[i: i + col] for i in range(0, len(msg_lst), col)]
        
            for _ in range(col):
                curr_idx = keyword.index(key_lst[k_indx])
                ciphertext += ''.join([row[curr_idx] for row in matrix])
                k_indx += 1

            enCipherText.insert("0.0", ciphertext)

        def decrypt():
            dePlainText.delete("0.0", "1.end")
            keyword = keywordText.get()
            ciphertext = deCipherText.get("0.0", "1.end")
            plaintext = ""
 
            k_indx = 0
            msg_indx = 0
            msg_len = float(len(ciphertext))
            msg_lst = list(ciphertext)
            col = len(keyword)
            row = int(math.ceil(msg_len / col))
            key_lst = sorted(list(keyword))
            dec_cipher = []
            for _ in range(row):
                dec_cipher += [[None] * col]
        
            for _ in range(col):
                curr_idx = keyword.index(key_lst[k_indx])
                for j in range(row):
                    dec_cipher[j][curr_idx] = msg_lst[msg_indx]
                    msg_indx += 1

                k_indx += 1
        
            try:
                plaintext = ''.join(sum(dec_cipher, []))
            except TypeError:
                raise TypeError("This program cannot",
                                "handle repeating words.")
        
            null_count = plaintext.count('_')
            if null_count > 0:
                plaintext = plaintext[: -null_count]

            dePlainText.insert("0.0", plaintext)

        def capture(*args):
            if keyword.get()!=' ':
                encryptbtn.configure(state='normal')
                decryptbtn.configure(state='normal')

            else:
                encryptbtn.configure(state='disabled')
                decryptbtn.configure(state='disabled')

        root.withdraw()
        self.screen = customtkinter.CTkToplevel(root)
        self.screen.title("COLUMNAR")
        self.screen.after(0, lambda:self.screen.state('zoomed'))

        keyword = StringVar()
        keyword.trace('w', capture)

        image = PIL.Image.open("columnar.png")
        background_image = customtkinter.CTkImage(image, size=(1515, 150))

        titleFrame = customtkinter.CTkFrame(master=self.screen, width=1500, height=150)
        titleFrame.grid(row=0, column=0, columnspan=4, padx=15, pady=15)
        title = customtkinter.CTkLabel(master=titleFrame, text="Columnar Transposition Cipher\n(Transposition)", font=('Arial',40,'bold'), image=background_image)
        title.place(relwidth=1, relheight=1)

        keywordLabel = customtkinter.CTkLabel(master=self.screen, text="Keyword: ", width=100, font=('Arial',25))
        keywordLabel.place(x=660, y=190)
        keywordText = customtkinter.CTkEntry(master=self.screen, textvariable=keyword, width=200, font=('Arial',25))
        keywordText.place(x=770, y=190)

        encryptionFrame = customtkinter.CTkFrame(master=self.screen, width=740, height=540)
        encryptionFrame.place(x=15, y=250)
        encryptionTitle = customtkinter.CTkLabel(master=encryptionFrame, text="Encryption", font=('Arial',25,'bold'))
        encryptionTitle.place(relwidth=1, y=10)
        PlainTextLabel = customtkinter.CTkLabel(master=encryptionFrame, text="Plaintext: ", width=100, font=('Arial',20))
        PlainTextLabel.place(x=10, y=30)
        enPlainText = customtkinter.CTkTextbox(master=encryptionFrame, width=720, height=190, font=('Arial',25,'bold'))
        enPlainText.place(x=10, y=60)
        CipherTextLabel = customtkinter.CTkLabel(master=encryptionFrame, text="Ciphertext: ", width=100, font=('Arial',20))
        CipherTextLabel.place(x=10, y=300)
        enCipherText = customtkinter.CTkTextbox(master=encryptionFrame, width=720, height=200, font=('Arial',25,'bold'))
        enCipherText.place(x=10, y=330)
        encryptbtn = customtkinter.CTkButton(master=encryptionFrame, text="Encrypt", state=DISABLED, width=720, height=30, font=('Arial',20,'bold'), command=encrypt)
        encryptbtn.place(x=10, y=260)

        decryptionFrame = customtkinter.CTkFrame(master=self.screen, width=740, height=540)
        decryptionFrame.place(x=775, y=250)
        decryptionTitle = customtkinter.CTkLabel(master=decryptionFrame, text="Decryption", font=('Arial',25,'bold'))
        decryptionTitle.place(relwidth=1, y=10)
        CipherTextLabel = customtkinter.CTkLabel(master=decryptionFrame, text="Ciphertext: ", width=100, font=('Arial',20))
        CipherTextLabel.place(x=10, y=30)
        deCipherText = customtkinter.CTkTextbox(master=decryptionFrame, width=720, height=190, font=('Arial',25,'bold'))
        deCipherText.place(x=10, y=60)
        PlainTextLabel = customtkinter.CTkLabel(master=decryptionFrame, text="Plaintext: ", width=100, font=('Arial',20))
        PlainTextLabel.place(x=10, y=300)
        dePlainText = customtkinter.CTkTextbox(master=decryptionFrame, width=720, height=200, font=('Arial',25,'bold'))
        dePlainText.place(x=10, y=330)
        decryptbtn = customtkinter.CTkButton(master=decryptionFrame, text="Decrypt", state=DISABLED, width=720, height=30, font=('Arial',20,'bold'), command=decrypt)
        decryptbtn.place(x=10, y=260)

        backbtn = customtkinter.CTkButton(master=self.screen, text="Back", width=100, height=25, font=('Arial',20,'bold'), command=self.main_window)
        backbtn.place(x=715, y=800)

    def AES_screen(self):
        def encrypt():
            def ECB(key_bytes, plaintext_bytes):
                cipher = AES.new(key_bytes, AES.MODE_ECB)
                padded_plaintext = pad(plaintext_bytes, AES.block_size)
                ciphertext_bytes = cipher.encrypt(padded_plaintext)
                ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
                return ciphertext
            
            def CBC(key_bytes, plaintext_bytes, iv_bytes):
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
                padded_plaintext = pad(plaintext_bytes, AES.block_size)
                ciphertext_bytes = cipher.encrypt(padded_plaintext)
                ciphertext = b64encode(iv_bytes + ciphertext_bytes).decode('utf-8')
                return ciphertext
            
            enCipherText.delete("0.0", "1.end")
            key = secKeyText.get()
            iv = IVText.get()
            plaintext = enPlainText.get("0.0", "1.end")
            key_bytes = codecs.encode(key, 'utf-8')
            iv_bytes = codecs.encode(iv, 'utf-8')
            plaintext_bytes = codecs.encode(plaintext, 'utf-8')
            mode = Mode.get()
            if (mode==1):
                ciphertext = ECB(key_bytes, plaintext_bytes)
            elif (mode==2):
                ciphertext = CBC(key_bytes, plaintext_bytes, iv_bytes)

            enCipherText.insert("0.0", ciphertext)

        def decrypt():
            def ECB(key_bytes, ciphertext_bytes):
                cipher = AES.new(key_bytes, AES.MODE_ECB)
                decrypted_bytes = cipher.decrypt(ciphertext_bytes)
                plaintext_bytes = unpad(decrypted_bytes, AES.block_size)
                plaintext = plaintext_bytes.decode('utf-8')
                return plaintext
            
            def CBC(key_bytes, ciphertext_bytes):
                iv = ciphertext_bytes[:AES.block_size]
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                ciphertext_bytes = ciphertext_bytes[AES.block_size:]
                decrypted_bytes = cipher.decrypt(ciphertext_bytes)
                plaintext_bytes = unpad(decrypted_bytes, AES.block_size)
                plaintext = plaintext_bytes.decode('utf-8')
                return plaintext
            
            dePlainText.delete("0.0", "1.end")
            key = secKeyText.get()
            ciphertext = deCipherText.get("0.0", "1.end")
            key_bytes = codecs.encode(key, 'utf-8')
            ciphertext_bytes = b64decode(ciphertext)
            mode = Mode.get()
            if (mode==1):
                plaintext = ECB(key_bytes, ciphertext_bytes)
            elif (mode==2):
                plaintext = CBC(key_bytes, ciphertext_bytes)

            dePlainText.insert("0.0", plaintext)

        def capture(*args):
            if Mode.get()==1 and len(SecKey.get())==16:
                encryptbtn.configure(state='normal')
                decryptbtn.configure(state='normal')
            elif Mode.get()==2 and len(SecKey.get())==16 and len(IV.get())==16:
                encryptbtn.configure(state='normal')
                decryptbtn.configure(state='normal')    
            else:
                encryptbtn.configure(state='disabled')
                decryptbtn.configure(state='disabled')

        root.withdraw()
        self.screen = customtkinter.CTkToplevel(root)
        self.screen.title("AES")
        self.screen.after(0, lambda:self.screen.state('zoomed'))

        Mode = IntVar()
        Mode.trace('w', capture)
        SecKey = StringVar()
        SecKey.trace('w', capture)
        IV = StringVar()
        IV.trace('w', capture)

        image = PIL.Image.open("aes.png")
        background_image = customtkinter.CTkImage(image, size=(1515, 150))

        titleFrame = customtkinter.CTkFrame(master=self.screen, width=1500, height=150)
        titleFrame.grid(row=0, column=0, columnspan=4, padx=15, pady=15)
        title = customtkinter.CTkLabel(master=titleFrame, text="Advanced Encryption Standard\n(AES)", font=('Arial',40,'bold'), image=background_image)
        title.place(relwidth=1, relheight=1)

        alert = customtkinter.CTkLabel(master=self.screen, text="*Secret key & IV must be 16 bytes long (16 characters)", text_color='red', font=('Arial',20,'bold'))
        alert.place(relwidth=1, y=170)
        secKeyLabel = customtkinter.CTkLabel(master=self.screen, text="Secret key: ", width=100, font=('Arial',25))
        secKeyLabel.place(x=340, y=200)
        secKeyText = customtkinter.CTkEntry(master=self.screen, textvariable=SecKey, width=250, font=('Arial',25))
        secKeyText.place(x=490, y=200)
        IVLabel = customtkinter.CTkLabel(master=self.screen, text="IV value: ", width=100, font=('Arial',25))
        IVLabel.place(x=790, y=200)
        IVText = customtkinter.CTkEntry(master=self.screen, textvariable=IV, width=250, font=('Arial',25))
        IVText.place(x=910, y=200)
        ModeLabel = customtkinter.CTkLabel(master=self.screen, text="Mode: ", width=50, font=('Arial',25))
        ModeLabel.place(x=610, y=250)
        ECBradiobutton = customtkinter.CTkRadioButton(master=self.screen, width=100, font=('Arial',25), text="ECB", variable=Mode, value=1)
        ECBradiobutton.place(x=710, y=250)
        CBCradiobutton = customtkinter.CTkRadioButton(master=self.screen, width=100, font=('Arial',25), text="CBC", variable=Mode, value=2)
        CBCradiobutton.place(x=810, y=250)

        encryptionFrame = customtkinter.CTkFrame(master=self.screen, width=740, height=490)
        encryptionFrame.place(x=15, y=300)
        encryptionTitle = customtkinter.CTkLabel(master=encryptionFrame, text="Encryption", font=('Arial',25,'bold'))
        encryptionTitle.place(relwidth=1, y=10)
        PlainTextLabel = customtkinter.CTkLabel(master=encryptionFrame, text="Plaintext: ", width=100, font=('Arial',20))
        PlainTextLabel.place(x=10, y=30)
        enPlainText = customtkinter.CTkTextbox(master=encryptionFrame, width=720, height=170, font=('Arial',25,'bold'))
        enPlainText.place(x=10, y=60)
        CipherTextLabel = customtkinter.CTkLabel(master=encryptionFrame, text="Ciphertext: ", width=100, font=('Arial',20))
        CipherTextLabel.place(x=10, y=280)
        enCipherText = customtkinter.CTkTextbox(master=encryptionFrame, width=720, height=170, font=('Arial',25,'bold'))
        enCipherText.place(x=10, y=310)
        encryptbtn = customtkinter.CTkButton(master=encryptionFrame, text="Encrypt", state=DISABLED, width=720, height=30, font=('Arial',20,'bold'), command=encrypt)
        encryptbtn.place(x=10, y=240)

        decryptionFrame = customtkinter.CTkFrame(master=self.screen, width=740, height=490)
        decryptionFrame.place(x=775, y=300)
        decryptionTitle = customtkinter.CTkLabel(master=decryptionFrame, text="Decryption", font=('Arial',25,'bold'))
        decryptionTitle.place(relwidth=1, y=10)
        CipherTextLabel = customtkinter.CTkLabel(master=decryptionFrame, text="Ciphertext: ", width=100, font=('Arial',20))
        CipherTextLabel.place(x=10, y=30)
        deCipherText = customtkinter.CTkTextbox(master=decryptionFrame, width=720, height=170, font=('Arial',25,'bold'))
        deCipherText.place(x=10, y=60)
        PlainTextLabel = customtkinter.CTkLabel(master=decryptionFrame, text="Plaintext: ", width=100, font=('Arial',20))
        PlainTextLabel.place(x=10, y=280)
        dePlainText = customtkinter.CTkTextbox(master=decryptionFrame, width=720, height=170, font=('Arial',25,'bold'))
        dePlainText.place(x=10, y=310)
        decryptbtn = customtkinter.CTkButton(master=decryptionFrame, text="Decrypt", state=DISABLED, width=720, height=30, font=('Arial',20,'bold'), command=decrypt)
        decryptbtn.place(x=10, y=240)

        backbtn = customtkinter.CTkButton(master=self.screen, text="Back", width=100, height=25, font=('Arial',20,'bold'), command=self.main_window)
        backbtn.place(x=715, y=800)

    def RSA_screen(self):
        def gcd(a, b):
            if (b == 0):
                return a
            else:
                return gcd(b, a % b)

        def xgcd(a, b):
            x, old_x = 0, 1
            y, old_y = 1, 0
            while (b != 0):
                quotient = a // b
                a, b = b, a - quotient * b
                old_x, x = x, old_x - quotient * x
                old_y, y = y, old_y - quotient * y

            return a, old_x, old_y

        def random_e(phi):
            while (True):
                e = random.randrange(2, phi)
                if (gcd(e, phi) == 1):
                    return e

        def generate_key():
            rand1 = random.randint(50, 300)
            rand2 = random.randint(50, 300)

            fo = open('prime_number.txt', 'r')
            lines = fo.read().splitlines()
            fo.close()

            prime1 = int(lines[rand1])
            prime2 = int(lines[rand2])
            n = prime1 * prime2
            phi = (prime1 - 1) * (prime2 - 1)
            e = random_e(phi)
            gcd, x, y = xgcd(e, phi)
            if (x < 0):
                d = x + phi
            else:
                d = x

            publickey.set((e, n))
            privatekey.set((d, n))

            f_public = open('public_key.txt', 'w')
            f_public.write(str(e) + '\n')
            f_public.write(str(n) + '\n')
            f_public.close()

            f_private = open('private_key.txt', 'w')
            f_private.write(str(d) + '\n')
            f_private.write(str(n) + '\n')
            f_private.close()

        def encrypt():
            enCipherText.delete("0.0", "1.end")
            key, n = pubKeyText.get().split()          
            key = int(key)
            n = int(n)
            message = enPlainText.get("0.0", "1.end")
            cipher = [pow(ord(char), key, n) for char in message]
            enCipherText.insert("0.0", cipher)

        def decrypt():
            dePlainText.delete("0.0", "1.end")
            key, n = priKeyText.get().split()          
            key = int(key)
            n = int(n)
            message = list(map(int, deCipherText.get("0.0", "1.end").split(" ")))
            message = [str(pow(char, key, n)) for char in message]
            plain = [chr(int(char2)) for char2 in message]
            dePlainText.insert("0.0", ''.join(plain))
        
        def capture(*args):
            if (publickey.get()!=' ' and privatekey.get()!=' '):
                encryptbtn.configure(state='normal')
                decryptbtn.configure(state='normal')
            else:
                encryptbtn.configure(state='disabled')
                decryptbtn.configure(state='disabled')

        root.withdraw()
        self.screen = customtkinter.CTkToplevel(root)
        self.screen.title("RSA")
        self.screen.after(0, lambda:self.screen.state('zoomed'))

        publickey = StringVar()
        publickey.trace('w', capture)
        privatekey = StringVar()
        publickey.trace('w', capture)

        image = PIL.Image.open("rsa.png")
        background_image = customtkinter.CTkImage(image, size=(1515, 150))

        titleFrame = customtkinter.CTkFrame(master=self.screen, width=1500, height=150)
        titleFrame.grid(row=0, column=0, columnspan=4, padx=15, pady=15)
        title = customtkinter.CTkLabel(master=titleFrame, text="Rivest-Shamir-Adleman\n(RSA)", font=('Arial',40,'bold'), image=background_image)
        title.place(relwidth=1, relheight=1)

        keybtn = customtkinter.CTkButton(master=self.screen, text="Generate", height=25, font=('Arial',25,'bold'), command=generate_key)
        keybtn.grid(row=1, column=1, columnspan=2, pady=10)
        pubKeyLabel = customtkinter.CTkLabel(master=self.screen, text="Public key: ", width=100, font=('Arial',25))
        pubKeyLabel.place(x=360, y=250)
        pubKeyText = customtkinter.CTkEntry(master=self.screen, textvariable=publickey, width=250, font=('Arial',25))
        pubKeyText.place(x=490, y=250)
        priKeyLabel = customtkinter.CTkLabel(master=self.screen, text="Private key: ", width=100, font=('Arial',25))
        priKeyLabel.place(x=790, y=250)
        priKeyText = customtkinter.CTkEntry(master=self.screen, textvariable=privatekey, width=250, font=('Arial',25))
        priKeyText.place(x=925, y=250)

        encryptionFrame = customtkinter.CTkFrame(master=self.screen, width=740, height=490)
        encryptionFrame.place(x=15, y=300)
        encryptionTitle = customtkinter.CTkLabel(master=encryptionFrame, text="Encryption", font=('Arial',25,'bold'))
        encryptionTitle.place(relwidth=1, y=10)
        PlainTextLabel = customtkinter.CTkLabel(master=encryptionFrame, text="Plaintext: ", width=100, font=('Arial',20))
        PlainTextLabel.place(x=10, y=30)
        enPlainText = customtkinter.CTkTextbox(master=encryptionFrame, width=720, height=170, font=('Arial',25,'bold'))
        enPlainText.place(x=10, y=60)
        CipherTextLabel = customtkinter.CTkLabel(master=encryptionFrame, text="Ciphertext: ", width=100, font=('Arial',20))
        CipherTextLabel.place(x=10, y=280)
        enCipherText = customtkinter.CTkTextbox(master=encryptionFrame, width=720, height=170, font=('Arial',25,'bold'))
        enCipherText.place(x=10, y=310)
        encryptbtn = customtkinter.CTkButton(master=encryptionFrame, text="Encrypt", state=DISABLED, width=720, height=30, font=('Arial',20,'bold'), command=encrypt)
        encryptbtn.place(x=10, y=240)

        decryptionFrame = customtkinter.CTkFrame(master=self.screen, width=740, height=490)
        decryptionFrame.place(x=775, y=300)
        decryptionTitle = customtkinter.CTkLabel(master=decryptionFrame, text="Decryption", font=('Arial',25,'bold'))
        decryptionTitle.place(relwidth=1, y=10)
        CipherTextLabel = customtkinter.CTkLabel(master=decryptionFrame, text="Ciphertext: ", width=100, font=('Arial',20))
        CipherTextLabel.place(x=10, y=30)
        deCipherText = customtkinter.CTkTextbox(master=decryptionFrame, width=720, height=170, font=('Arial',25,'bold'))
        deCipherText.place(x=10, y=60)
        PlainTextLabel = customtkinter.CTkLabel(master=decryptionFrame, text="Plaintext: ", width=100, font=('Arial',20))
        PlainTextLabel.place(x=10, y=280)
        dePlainText = customtkinter.CTkTextbox(master=decryptionFrame, width=720, height=170, font=('Arial',25,'bold'))
        dePlainText.place(x=10, y=310)
        decryptbtn = customtkinter.CTkButton(master=decryptionFrame, text="Decrypt", state=DISABLED, width=720, height=30, font=('Arial',20,'bold'), command=decrypt)
        decryptbtn.place(x=10, y=240)

        backbtn = customtkinter.CTkButton(master=self.screen, text="Back", width=100, height=25, font=('Arial',20,'bold'), command=self.main_window)
        backbtn.place(x=715, y=800)

    def SHA_screen(self):
        K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

        def hashing():
            hashedText.delete("0.0", "1.end")
            messagetext = messageText.get("0.0", "1.end")
            hashedtext = generate_hash(messagetext).hex()
            hashedText.insert("0.0", hashedtext)

        def generate_hash(message: bytearray) -> bytearray:
            if isinstance(message, str):
                message = bytearray(message, 'ascii')
            elif isinstance(message, bytes):
                message = bytearray(message)
            elif not isinstance(message, bytearray):
                raise TypeError

            length = len(message) * 8
            message.append(0x80)
            while (len(message) * 8 + 64) % 512 != 0:
                message.append(0x00)

            message += length.to_bytes(8, 'big')
            assert (len(message) * 8) % 512 == 0, "Padding did not complete properly!"
            blocks = []
            for i in range(0, len(message), 64):
                blocks.append(message[i:i+64])

            h0 = 0x6a09e667
            h1 = 0xbb67ae85
            h2 = 0x3c6ef372
            h3 = 0xa54ff53a
            h5 = 0x9b05688c
            h4 = 0x510e527f
            h6 = 0x1f83d9ab
            h7 = 0x5be0cd19

            for message_block in blocks:
                message_schedule = []
                for t in range(0, 64):
                    if t <= 15:
                        message_schedule.append(bytes(message_block[t*4:(t*4)+4]))
                    else:
                        term1 = _sigma1(int.from_bytes(message_schedule[t-2], 'big'))
                        term2 = int.from_bytes(message_schedule[t-7], 'big')
                        term3 = _sigma0(int.from_bytes(message_schedule[t-15], 'big'))
                        term4 = int.from_bytes(message_schedule[t-16], 'big')

                        schedule = ((term1 + term2 + term3 + term4) % 2**32).to_bytes(4, 'big')
                        message_schedule.append(schedule)

                assert len(message_schedule) == 64

                a = h0
                b = h1
                c = h2
                d = h3
                e = h4
                f = h5
                g = h6
                h = h7

                for t in range(64):
                    t1 = ((h + _capsigma1(e) + _ch(e, f, g) + K[t] +
                        int.from_bytes(message_schedule[t], 'big')) % 2**32)
                    t2 = (_capsigma0(a) + _maj(a, b, c)) % 2**32
                    h = g
                    g = f
                    f = e
                    e = (d + t1) % 2**32
                    d = c
                    c = b
                    b = a
                    a = (t1 + t2) % 2**32

                h0 = (h0 + a) % 2**32
                h1 = (h1 + b) % 2**32
                h2 = (h2 + c) % 2**32
                h3 = (h3 + d) % 2**32
                h4 = (h4 + e) % 2**32
                h5 = (h5 + f) % 2**32
                h6 = (h6 + g) % 2**32
                h7 = (h7 + h) % 2**32

            return ((h0).to_bytes(4, 'big') + (h1).to_bytes(4, 'big') +
                    (h2).to_bytes(4, 'big') + (h3).to_bytes(4, 'big') +
                    (h4).to_bytes(4, 'big') + (h5).to_bytes(4, 'big') +
                    (h6).to_bytes(4, 'big') + (h7).to_bytes(4, 'big'))

        def _sigma0(num: int):
            num = (_rotate_right(num, 7) ^
                _rotate_right(num, 18) ^
                (num >> 3))
            return num

        def _sigma1(num: int):
            num = (_rotate_right(num, 17) ^
                _rotate_right(num, 19) ^
                (num >> 10))
            return num

        def _capsigma0(num: int):
            num = (_rotate_right(num, 2) ^
                _rotate_right(num, 13) ^
                _rotate_right(num, 22))
            return num

        def _capsigma1(num: int):
            num = (_rotate_right(num, 6) ^
                _rotate_right(num, 11) ^
                _rotate_right(num, 25))
            return num

        def _ch(x: int, y: int, z: int):
            return (x & y) ^ (~x & z)

        def _maj(x: int, y: int, z: int):
            return (x & y) ^ (x & z) ^ (y & z)

        def _rotate_right(num: int, shift: int, size: int = 32):
            return (num >> shift) | (num << size - shift)
        
        def verify():
            resultText.delete("0.0", "1.end")
            hashedtext = hashedText.get("0.0", "1.end")
            verifymessagetext = verifymessageText.get("0.0", "1.end")
            resulttext = hashlib.sha256(verifymessagetext.encode()).hexdigest()

            if (resulttext == hashedtext):
                resultText.insert("0.0", "The message / password matched")
            else:
                resultText.insert("0.0", "The message / password didn't matched")

        root.withdraw()
        self.screen = customtkinter.CTkToplevel(root)
        self.screen.title("SHA256")
        self.screen.after(0, lambda:self.screen.state('zoomed'))

        image = PIL.Image.open("sha.png")
        background_image = customtkinter.CTkImage(image, size=(1515, 200))

        titleFrame = customtkinter.CTkFrame(master=self.screen, width=1500, height=150)
        titleFrame.grid(row=0, column=0, columnspan=2, padx=15, pady=15)
        title = customtkinter.CTkLabel(master=titleFrame, text="Secure Hash Algorithm 256-bit\n(SHA256)", font=('Arial',40,'bold'), image=background_image)
        title.place(relwidth=1, relheight=1)

        hashingFrame = customtkinter.CTkFrame(master=self.screen, width=740, height=600)
        hashingFrame.grid(row=1, column=0, columnspan=1, padx=10, pady=10)
        hashingTitle = customtkinter.CTkLabel(master=hashingFrame, text="Hashing", font=('Arial',25,'bold'))
        hashingTitle.place(relwidth=1, y=10)
        messageLabel = customtkinter.CTkLabel(master=hashingFrame, text="Message / password", font=('Arial',20))
        messageLabel.place(relwidth=1, y=40)
        messageText = customtkinter.CTkTextbox(master=hashingFrame, width=720, height=210, font=('Arial',25,'bold'))
        messageText.place(x=10, y=80)
        hashedLabel = customtkinter.CTkLabel(master=hashingFrame, text="Hashed message / password", font=('Arial',20))
        hashedLabel.place(relwidth=1, y=340)
        hashedText = customtkinter.CTkTextbox(master=hashingFrame, width=720, height=210, font=('Arial',25,'bold'))
        hashedText.place(x=10, y=380)
        hashtbtn = customtkinter.CTkButton(master=hashingFrame, text="Generate hash", width=720, height=30, font=('Arial',20,'bold'), command=hashing)
        hashtbtn.place(x=10, y=300)

        verifyingFrame = customtkinter.CTkFrame(master=self.screen, width=740, height=600)
        verifyingFrame.grid(row=1, column=1, columnspan=1, padx=10, pady=10)
        verifyingTitle = customtkinter.CTkLabel(master=verifyingFrame, text="Verification", font=('Arial',25,'bold'))
        verifyingTitle.place(relwidth=1, y=10)
        verifymessageLabel = customtkinter.CTkLabel(master=verifyingFrame, text="Message / password", font=('Arial',20))
        verifymessageLabel.place(relwidth=1, y=40)
        verifymessageText = customtkinter.CTkTextbox(master=verifyingFrame, width=720, height=210, font=('Arial',25,'bold'))
        verifymessageText.place(x=10, y=80)
        resultLabel = customtkinter.CTkLabel(master=verifyingFrame, text="Result", font=('Arial',20))
        resultLabel.place(relwidth=1, y=340)
        resultText = customtkinter.CTkTextbox(master=verifyingFrame, width=720, height=210, font=('Arial',25,'bold'))
        resultText.place(x=10, y=380)
        verifytbtn = customtkinter.CTkButton(master=verifyingFrame, text="Verify", width=720, height=30, font=('Arial',20,'bold'), command=verify)
        verifytbtn.place(x=10, y=300)

        backbtn = customtkinter.CTkButton(master=self.screen, text="Back", width=100, height=25, font=('Arial',20,'bold'), command=self.main_window)
        backbtn.place(x=715, y=800)

if __name__ == "__main__":
    root = customtkinter.CTk()
    home = Home(root)
    root.mainloop()