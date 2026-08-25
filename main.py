from utils import formatter
from modules import http_headers, dns_scanner

def main():
    formatter.banner("CLI Multipurpose Tool")

    while True:
        print("Select a module to run:")
        print("1. HTTP Headers")
        print("2. DNS Scanner")
        print("3. Exit")
        choice = input("Enter your choice: ").strip().lower()

        if choice == "1":
            http_headers.run()
        elif choice == "2":
            dns_scanner.run()
        elif choice == "3":
            print("Exiting...")
            break
        else:
            formatter.error("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()