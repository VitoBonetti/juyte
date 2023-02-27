from scapy.utils import mac2str
import binascii
import netifaces
# import random
# import string
# import pyperclip
from colorama import Fore


API_ENDPOINT = 'https://hashes.com/en/api/identifier'

# Setting colors

error = Fore.RED
info = Fore.YELLOW
normal = Fore.CYAN
good = Fore.GREEN
reset = Fore.RESET
logo = Fore.LIGHTYELLOW_EX

# ASCII Logo

LOGO = r"""
      _             _
     | |_   _ _   _| |_ ___
  _  | | | | | | | | __/ _ \
| |_| | |_| | |_| | ||  __/
  \___/ \__,_|\__, |\__\___|
              |___/
                        v 0.1
"""

# clear screen function


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def check_hash():
    condition = True
    clear_screen()
    print(f"{normal}[*] Checking hash...{reset}")
    while condition:
        hash_value = input(f"{info}[*] Enter hash value: {reset}")
        if hash_value.lower() == "exit":
            main_menu()
        params = {'hash': hash_value}
        try:
            response = requests.get(API_ENDPOINT, params=params)
            # print(response)
            if response.status_code == 200:
                data = response.json()
                # print(data)
                if data['success']:
                    print(f"{normal}[+] Hash recognized:{reset} {good}{data['algorithms'][0]}{reset}")
                else:
                    print(f"{error}[!] Hash not recognized{reset}")
            else:
                print(f"{error}[!] Error {response.status_code}: {response.text}{reset}")
        except requests.exceptions.RequestException as e:
            print(f"{error}[-] Error: {e}{reset}")
        choice = input(f"{normal}[*] Do you want to check another hash? (Y/N): {reset}").lower()
        if choice == "n":
            clear_screen()
            main_menu()
            condition = False
        elif choice == "y":
            clear_screen()
            continue
        else:
            clear_screen()
            print(f"{error}[!] Invalid choice, please enter Y, or N{reset}")

def get_interface():

    interfaces = netifaces.interfaces()
    print(f"{normal}[*] Available network interfaces: {reset}")
    for i, iface in enumerate(interfaces):
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ip = addrs[netifaces.AF_INET][0]["addr"]
            print(f"{info}[{i}] {iface} ({ip}){reset}")
    while True:
        choice = input(f"\n{info}[*] Enter the number of the interface you want to use: {reset}")
        if choice.isdigit() and int(choice) < len(interfaces):
            return interfaces[int(choice)]


def scan_for_hosts():
    condition = True
    clear_screen()
    iface = get_interface()
    while condition:
        network = input(f"{info}[*] Enter a network address (CIDR format):")
        try:
            network = ipaddress.ip_network(network)
        except ValueError as e:
            clear_screen()
            print(e)
            print(f"{error}[!] Invalid network address. Please enter a valid CIDR address.{reset}")
            continue
        clear_screen()
        print(f"{normal}[*] Scanning network...{reset}")
        arp = ARP(pdst=network)
        iface_mac = ""
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_LINK in addrs:
            hwaddr = addrs[netifaces.AF_LINK][0]["addr"]
            if hwaddr != "00:00:00:00:00:00":
                iface_mac = binascii.hexlify(bytes.fromhex(hwaddr.replace(':', ''))).decode('utf-8')
        if not iface_mac:
            print(f"{error}[!] Could not find valid MAC address for interface {iface}{reset}")
            choice = input(f"{normal}[*] Do you want to continue without scanning? (Y/N): {reset}").lower()
            if choice == "n":
                clear_screen()
                main_menu()
                condition = False
            elif choice == "y":
                clear_screen()
                continue
            else:
                clear_screen()
                print(f"{error}[!] Invalid choice, please enter Y, or N{reset}")
                continue

        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=binascii.unhexlify(iface_mac.replace(':', '')))
        packet = ether/arp
        ether.summary()
        result = srp(packet, timeout=3, verbose=0)[0]

        if result:
            print(f"{good}[+] The following host(s) are alive:{reset}")
            for sent, received in result:
                print(f"{info}[+] {received.psrc}{reset}")
        else:
            print(f"{error}[!] No hosts are up{reset}")
        choice = input(f"{normal}[*] Do you want to scan another network? (Y/N): {reset}").lower()
        if choice == "n":
            clear_screen()
            main_menu()
            condition = False
        elif choice == "y":
            clear_screen()
            continue
        else:
            clear_screen()
            print(f"{error}[!] Invalid choice, please enter Y, or N{reset}")



def main_menu():
    condition = True
    while condition:
        print(f"{normal}Main Menu{reset}\n")
        print(f"{normal}[1] Check hash{reset}")
        print(f"{normal}[2] Scan for Host{reset}")
        print(f"{normal}[3] Exit{reset}\n")
        choice = input(f"{info}Enter your choice: {reset}")

        if choice == "1":
            check_hash()
        elif choice == "2":
            scan_for_hosts()
        elif choice == "3":
            clear_screen()
            print(f"{good}[*] Goodbye!{reset}")
            sys.exit()
        else:
            print(f"{error}[!] Invalid choice, please enter 1, 2 or 3{reset}")


def main():
    clear_screen()
    print(f"{logo}{LOGO}{reset}")
    main_menu()

# Start the script


if __name__ == "__main__":
    main()
