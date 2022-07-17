from venv import create
from cryptography.fernet import Fernet
import os, hashlib, time, sys

from colorama import Fore

def check_wallet():
    if os.path.exists("PLEASE_SAVE_THIS_FOLDER_IN_A_SECURE_DEVICE/key.key") == False:
        os.mkdir("PLEASE_SAVE_THIS_FOLDER_IN_A_SECURE_DEVICE")
        generate_key()
    

def generate_key():
    print("Generating key...")

    key = Fernet.generate_key()

    with open("PLEASE_SAVE_THIS_FOLDER_IN_A_SECURE_DEVICE/key.key", "wb") as key_file:
        key_file.write(key)

    print("Key generated..")
    print(Fore.RED + "/!\ PLEASE, SAVE THIS KEY IN A SECURE DEVICE /!\\" + Fore.RESET)


def load_key(path="PLEASE_SAVE_THIS_FOLDER_IN_A_SECURE_DEVICE/"):
    return open(f"{path}key.key", "rb").read()

# message = "Test"
# nonce = 0
# while True:
#     hash = hashlib.sha256((message + str(nonce)).encode())
#     if hash.hexdigest()[:2] == '00':
#         print(f"Hash founded : {hash.hexdigest()}")
#         break
#     print(hash.hexdigest(), end="\r")
#     nonce += 1
#     time.sleep(0.05)