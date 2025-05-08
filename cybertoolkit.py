import re
import socket
import hashlib
import os
import pyfiglet
import time
import itertools
from colorama import init, Fore, Style

init(autoreset=True)  # prevent color bleeding into any unnecessary print statements

def check_password_strength(password):
    score = 0
    if len(password) >= 8:
        score += 2
    if re.search(r"[A-Z]", password):
        score += 2
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 3
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 4

    if score <= 4:
        print(Fore.RED + "Password Strength: Weak")
    elif 5 <= score < 8:
        print(Fore.YELLOW + "Password Strength: Moderate")
    elif score >= 8:
        print(Fore.GREEN + "Password Strength: Strong")

def hash_file(file_path, algorithm="sha256"):  # '= "sha256"' passed in function to ensure a default fallback
    # check existence of file (os module)
    if not os.path.isfile(file_path):
        print(Fore.RED + "File does not exist")
        return

    if algorithm == "md5":
        hash = hashlib.md5()
    elif algorithm == "sha1":
        hash = hashlib.sha1()
    else:
        hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                hash.update(chunk)
        print(Fore.GREEN + f"\n {algorithm.upper()} Hash of the file:")
        print(Fore.YELLOW + hash.hexdigest())

        # ask a user if they want to compare the hash with a known hash
        compare = input(Fore.CYAN + "Do you want to compare the hash with a known hash? (y/n): ").lower()
        if compare == "y":
            known_hash = input(Fore.BLUE + "Enter the known hash: ")
            if hash.hexdigest() == known_hash.strip():
                print(Fore.GREEN + "Hashes match!")
            else:
                print(Fore.RED + "Hashes do not match.")
        elif compare == "n":
            print(Fore.YELLOW + "Exiting hash comparison.")
        else:
            print(Fore.RED + "Invalid choice. Exiting hash comparison.")
    except Exception as e:
        print(Fore.RED + f"Error: {str(e)}")
def scan_single_port(): 
    target = input(Fore.BLUE + "Enter the target IP address: ").strip()
    ip_version = input(Fore.BLUE + "Enter the IP version:\n[1]IPv4\n[2]IPv6 ").strip()
    if ip_version == "1" or ip_version == "ipv4" or ip_version == "IPv4":
        family = socket.AF_INET
    elif ip_version == "2" or ip_version == "ipv6" or ip_version == "IPv6":
        family = socket.AF_INET6 
    else:
        print(Fore.RED + "Invalid IP version.")
        return
    protocol = input(Fore.YELLOW + "Enter the protocol:\n[1]TCP\n[2]UDP ").strip()
    if protocol == "tcp" or protocol == "TCP" or protocol == "1":
        sock_type = socket.SOCK_STREAM
    elif protocol == "udp" or protocol == "2" or protocol == "UDP":    
        sock_type = socket.SOCK_DGRAM
    else:
        print(Fore.RED + "Invalid protocol. Please enter 'tcp' or 'udp'.")
        return
    print(Fore.MAGENTA + f"\n Scanning ports 1-1024 on {target} using {protocol.upper()} protocol...\n")
    for port in range(1, 1024):
        try:
            sock = socket.socket(family, sock_type)
            sock.settimeout(0.9)
            if protocol == "2" or protocol == "tcp" or protocol == "TCP":
                result = sock.connect_ex((target,port))
                if result == 0:
                    print(Fore.GREEN + f"Port {port} is open on {protocol.upper()} protocol")
            else:
                try:
                    sock.sendto(b"", (target, port)) # b"" send bytes
                    sock.settimeout(0.9) 
                    sock.recvfrom(80) 
                    print(Fore.GREEN + f"Port {port} is open on {protocol.upper()} protocol")
                
                except socket.timeout:
                    print(Fore.GREEN + f"Port {port} (No Response)")
                except Exception as e:
                    pass
            sock.close()
        except Exception as e:
            print(Fore.RED + f"Error on port {port}: {e}")
    print(Fore.CYAN + "Scan Complete.")



                

rainbow_colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]

def print_rainbow(text):
    color_cycle = itertools.cycle(rainbow_colors)  # This will loop through the rainbow colors
    for char in text:
        print(next(color_cycle) + char, end="", flush=True)
        time.sleep(0.00003)  
    print()  

ascii_banner = pyfiglet.figlet_format("CyberToolKit")
print_rainbow(ascii_banner)

print(Fore.CYAN + Style.BRIGHT + "\n" + "=" * 40)
print("🔐 Welcome to " + Fore.MAGENTA + "CyberToolkit".center(25))
print(Fore.CYAN + "=" * 40 + "\n")

print(Fore.CYAN + "=== Menu ===")
print(Fore.BLUE + "[1]. Password Strength Checker")
print(Fore.RED + "[2]. File Hash Checker")
print(Fore.GREEN + "[3]. Port Scanner")
print(Fore.YELLOW + "[4]. Exit\n")
print(Fore.CYAN + "=====================")

choice = input(Fore.LIGHTBLACK_EX + "Choose an option (1-4): ")

if choice == "1":
    password_to_check = input(Fore.BLUE + Style.BRIGHT + "Input password to check: ")
    check_password_strength(password_to_check)
elif choice == "2":
    file_path = input(Fore.BLUE + "Enter full file path to generate hash: ")
    print(Fore.CYAN + "Choose hashing algorithm:")
    print(Fore.LIGHTGREEN_EX + "[1] MD5\n[2] SHA-1\n[3] SHA256")
    algorithm_choice = input(Fore.LIGHTBLACK_EX + "Choose an algorithm (1-3): ")
    algorithm_map = {
        "1": "md5",
        "2": "sha1",
        "3": "sha256"
    }
    algo = algorithm_map.get(algorithm_choice, "sha256")  # default algorithm at key of .get() function
    hash_file(file_path, algo)
elif choice == "3":
    print(Fore.CYAN + "Port Scanner")
    print(Fore.YELLOW + "Scan ports 1-1024")
    scan_single_port()
elif choice == "4":
    print(Fore.MAGENTA + "Exiting program...")
    exit(0)
else:
    print(Fore.RED + "Invalid Choice")
