from Cryptodome import Random
from Cryptodome.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join
import time

class encryptorAlgorithm:
    def __init__(self, key):
        self.key = key

    # Padding is the way of taking data that may or may not be the same size as the block size for a encryptingCypher and extending it, so that it becomes a multiple of the
    # block size of the cypher

    # Eg: The block size is 16
    # So if we have a string "hello world", the padding function will pad this string to extend it to 16 bytes -> "hello world\x00\x00\x00\x00\x00"
    def padding(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


    # Key is used to encrypt the data. If we encrypt with one key, we can only decryptionAlgo with that key only
    def encryptionAlgo(self, messagebits, key, key_size=256):
        messagebits = self.padding(messagebits)
        # iv = Initialisation Vector
        # The randomized value will be of the form, b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'.
        # It is a random string of AES Block Size
        iv = Random.new().read(AES.block_size)
        # Mode CBC stands for Cipher-Block Chaining
        encryptingCypher = AES.new(key, AES.MODE_CBC, iv)
        # The cyphered message is then appended to the randomised init vector 
        return iv + encryptingCypher.encrypt(messagebits)

    def encryptionAlgo_file(self, fileName):
        # We open the file in binary file for reading
        with open(fileName, 'rb') as fi:
            # Reads the text contained in the .txt file
            plaintext = fi.read()
        encrypted = self.encryptionAlgo(plaintext, self.key)
        with open(fileName + ".enc", 'wb') as fo:
            # The encrypted data is added to a new file which has a .enc extension
            fo.write(encrypted)
        # The original file is deleted
        os.remove(fileName)

    def decryptionAlgo(self, encryptingCyphertext, key):
        # As we appended the iv string with the encrypted data in the encryption function, we will
        # seperate it out here to get the original iv string
        iv = encryptingCyphertext[:AES.block_size]
        # We generate an encrypting cypher object again using the key and the iv
        encryptingCypher = AES.new(key, AES.MODE_CBC, iv)
        # The generated cypher object is then used to decrypt the end of the cypher text, i.e, not the iv string, but the actual encrypted data
        # hence we use [AES.block_size:]
        plaintext = encryptingCypher.decrypt(encryptingCyphertext[AES.block_size:])
        # rstrip removes the padding that we did
        return plaintext.rstrip(b"\0")

    def decryptionAlgo_file(self, fileName):
        # We read all the encrypted data
        with open(fileName, 'rb') as fo:
            encryptingCyphertext = fo.read()
        # We decrypt the encrypted cypher text using our key
        decrypted = self.decryptionAlgo(encryptingCyphertext, self.key)
        # We create a new file, which is the same name as our .enc file but without the last 4 letters, '.enc' to get the original file name
        with open(fileName[:-4], 'wb') as fo:
            fo.write(decrypted)
        # Here we delete the .enc file
        os.remove(fileName)

    def getAllFiles(self):
        # This function returns a list of the paths on the files in the current directory and their sub directories
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subdirList, fileList in os.walk(dir_path):
            for fname in fileList:
                # We remove script.py from the list so as to not encrypt the python script we are using tor encrypt all other files.
                if (fname != 'script.py' and fname != 'data.txt.enc'):
                    dirs.append(dirName + "\\" + fname)
        return dirs

    def encryptionAlgo_all_files(self):
        # Runs the encryption algo on all the files in the directory
        dirs = self.getAllFiles()
        for fileName in dirs:
            self.encryptionAlgo_file(fileName)

    def decryptionAlgo_all_files(self):
        # Runs the decryption algo on all the files in the directory
        dirs = self.getAllFiles()
        for fileName in dirs:
            self.decryptionAlgo_file(fileName)

# We define our key here
key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
enc = encryptorAlgorithm(key)

# Checks whether the data.txt, which contains the encrypted password, file is already encrypted. If it is, then it asks for the password and decrypts the data.txt
# to check whether the entered password is right.
if os.path.isfile('data.txt.enc'):
    while True:
        password = str(input("Enter the password: "))
        enc.decryptionAlgo_file("data.txt.enc")
        p = ''
        with open("data.txt", "r") as f:
            p = f.readlines()
        if p[0] == password:
            enc.encryptionAlgo_file("data.txt")
            break

    while True:
        
        choice = int(input(
            "Enter your choice of action:\n\t1. Encrypt file.\n\t2. Decrypt file.\n\t3. Encrypt all files in the directory.\n\t4. Decrypt all files in the directory.\n\t5. Exit.\n"))
        if choice == 1:
            enc.encryptionAlgo_file(str(input("Enter the name of the file you wish to encrypt: ")))
        elif choice == 2:
            enc.decryptionAlgo_file(str(input("Enter the name of the file you wish to decrypt: ")))
        elif choice == 3:
            enc.encryptionAlgo_all_files()
        elif choice == 4:
            enc.decryptionAlgo_all_files()
        elif choice == 5:
            exit()
        else:
            print("Please choose a valid option.")

# If the file is not encrypted, it prompts the user for a new password which is then stored in data.txt and then encrypted.
else:
    while True:
        password = str(input("Please enter a password. It will be used to encrypt and decrypt your files: "))
        passwordChecker = str(input("Confirm your password: "))
        if password == passwordChecker:
            break
        else:
            print("Passwords don't match.")
    f = open("data.txt", "w+")
    f.write(password)
    f.close()
    enc.encryptionAlgo_file("data.txt")
    time.sleep(15)