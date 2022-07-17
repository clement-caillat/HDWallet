import os, sys, random, json, security, glob, hashlib, base58, datetime, socket
from colorama import Fore
from ecdsa.util import PRNG
from ecdsa import SigningKey, VerifyingKey
from cryptography.fernet import Fernet


def get_amount(wallet):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 9988))
    print("Getting balance")
    s.sendall(bytes(wallet,encoding="utf-8"))
    rcv = s.recv(1025)
    amount = rcv.decode("utf-8")
    s.close()
    return amount

def load_address():
    print("Loading address...")
    if not os.path.exists("Wallets/"):
        os.mkdir("Wallets")
    if not glob.glob("Wallets/*"):
        a = input("No address found ! Would you like to create one ? [Y/N] : ")
        if a == "Y" or a == "y" or a == "yes":
            name = input("Name your wallet : ")
            create_address(name)
        else:
            print("Log out")
            sys.exit(0)    

    name = input("Enter the name of the wallet : ")

    if name == '0000':
        name = input("Name your wallet : ")
        create_address(name)

    return load_wallet(name) 

def load_wallet(name):
    fernet = Fernet(security.load_key())
    
    with open(f"Wallets/{name}.wlt", 'rb') as f:
        data = f.read()
        decrypted = fernet.decrypt(data)
        return json.loads(decrypted.decode())

def create_address(name):
    print("Creating address...")
    private_key = generate_private_key()
    
    pk = private_key.verifying_key

    public_key_hex = pk.to_string().hex().encode()

    public_key = (b'04' + public_key_hex).decode("utf-8")

    if (ord(bytearray.fromhex(public_key[-2:])) % 2 == 0):
        public_key_compressed = '02'
    else:
        public_key_compressed = '03'

    public_key_compressed += public_key[2:66]

    hex_str = bytearray.fromhex(public_key_compressed)
    sha = hashlib.sha256()
    sha.update(hex_str)
    
    rip = hashlib.new('ripemd160')
    rip.update(sha.digest())
    key_hash = rip.hexdigest()

    modified_key_hash = "00" + key_hash

    sha = hashlib.sha256()
    hex_str = bytearray.fromhex(modified_key_hash)
    sha.update(hex_str)
    sha.hexdigest()

    sha_2 = hashlib.sha256()
    sha_2.update(sha.digest())
    sha_2.hexdigest()

    checksum = sha_2.hexdigest()[:8]
    
    byte_25_address = modified_key_hash + checksum

    address = base58.b58encode(bytes(bytearray.fromhex(byte_25_address))).decode('utf-8')


    data = {
        'private_key': private_key.to_pem(point_encoding="compressed").decode(),
        'public_key': pk.to_pem(point_encoding="compressed").decode(),
        'address': address
    }

    with open(f'Wallets/{name}.wlt', 'w') as f:
        json.dump(data, f)

    fernet = Fernet(security.load_key())

    with open(f"Wallets/{name}.wlt", 'rb') as f:
        original = f.read()

    encrypted = fernet.encrypt(original)

    with open(f"Wallets/{name}.wlt", 'wb') as f:
        f.write(encrypted)

def pick_words():
    with open('./words.txt', 'r') as f:
        random_words = []

        with open('./words.txt', 'r') as f:
            allText = f.read()
            words = list(map(str, allText.split()))

            for i in range(12):
                random_words.append(random.choice(words))

    return random_words

def generate_private_key():
    words = pick_words()
    rng = PRNG(''.join(words).encode())
    private_key = SigningKey.generate(entropy=rng)

    print(f"Your passphrase : {' '.join(words)}")
    name = input("Passphrase file name : ")
    with open(f"PLEASE_SAVE_THIS_FOLDER_IN_A_SECURE_DEVICE/{name}.txt", 'w') as f:
        f.write(' '.join(words))

    return private_key

def make_transaction(wallet):
    
    private_key = SigningKey.from_pem(wallet['private_key'])
    public_key = VerifyingKey.from_pem(wallet['public_key'])
    amount = input("Enter the amount (DLT): ")
    receiver = input("Enter the receiver address : ")
    date = datetime.datetime.now().timestamp()

    transaction_raw = f"{date}.{wallet['address']}.{public_key.to_string().hex()}.{amount}.{receiver}"

    signature = private_key.sign(transaction_raw.encode())

    transaction = {
        "date": date,
        "sender": wallet['address'],
        "amount": amount,
        "receiver": receiver,
        "signature": signature.hex(),
        "public_key": public_key.to_string().hex(),
        "transaction_raw": transaction_raw,
        "transaction_hash": hashlib.sha256(transaction_raw.encode()).hexdigest()
    }

    verify_transaction(transaction)


def verify_transaction(transaction):
    signature = bytes.fromhex(transaction["signature"])
    public_key = VerifyingKey.from_string(bytes.fromhex(transaction["public_key"]))
    try:
        public_key.verify(signature, transaction["transaction_raw"].encode())
        print(f"{Fore.GREEN}Signature is valid{Fore.RESET}")
    except:
        print(f"{Fore.RED}Bad signature{Fore.RESET}")

    c = input(f"ARE YOU SURE TO SEND {transaction['amount']} to {transaction['receiver']} ? [Y/N]")

    if c == 'YES' or c == 'Y' or c == 'yes' or c == 'y':
        print("Sending transaction...")
        mine_transaction(transaction)
    else:
        print("Cancelling transaction")

def mine_transaction(transaction):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 9988))
    t = json.dumps(transaction)
    s.sendall(bytes(t,encoding="utf-8"))
    rcv = s.recv(1025)
    status = rcv.decode("utf-8")

    if status:
        print("Transaction success")
    else:
        print("Transaction failed")
    s.close()
