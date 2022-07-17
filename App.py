import security, Wallet, os, sys

def run():
    init()
    security.check_wallet()
    wallet = Wallet.load_address()
    amount = Wallet.get_amount(wallet['address'])

    while True:
        os.system('cls')
        amount = Wallet.get_amount(wallet['address'])
        print(f"Your wallet address : {wallet['address']}")
        print(f"Current balance : {amount} DLT")
        print("-----------------")
        print("1.Make a transaction")
        print("0.Exit")
        choice = input("Choice : ")

        if choice == str(0):
            print("Log out")
            sys.exit(0)
        elif choice == str(1):
            Wallet.make_transaction(wallet)

def init():
    if os.path.exists("Wallets") == False:
        os.mkdir("Wallets")