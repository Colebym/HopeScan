import ipaddress
import socket
import time
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def menu():
    print("1 - Scan an IP Address")
    print("2 - Scan a domain name")
    print("3 - Exit")

    while True:
        try:
            scan_option = int(input(">> "))
            break
        except ValueError:
            print("Please enter a valid number.")

    if scan_option == 1:
        ip()
    elif scan_option == 2:
        dom()
    elif scan_option == 3:
        exit()

def port_selection():
    print("\n- Select Port Range -")
    print("1 - Default (1-1024)")
    print("2 - Custom Range")

    while True:
        port_choice = int(input(">> "))

        if port_choice == 1:
            return 1, 1024
        elif port_choice == 2:
            while True:
                try:
                    start_port = int(input("\nEnter start port (1-65535): "))
                    end_port = int(input("Enter end port (1-65535): "))

                    if 1 <= start_port <= end_port <= 65535:
                        return start_port, end_port
                    else:
                        print("Invalid range, try again.")
                except ValueError:
                    print("Please enter valid integers.")

        else:
            print("Invalid choice, please try again.")

def ip(): # Takes IP input
    ip_valid = False

    while ip_valid == False: # Loop to validate IP Address input is correct
        target_ip = input("\nEnter target IP: ")

        try:
            ipaddress.IPv4Address(target_ip) # Valid IP
            ip_valid = True

        except ipaddress.AddressValueError: # Invalid IP
            ip_valid = False
            print("Invalid IP Address, please try again...")

    if ip_valid:
        start_port, end_port = port_selection() # Gets start and end ports
        scan_ports(target_ip, start_port, end_port)  # Calls port scan function, passing start and end ports


def dom():
    domain_valid = False

    while not domain_valid:
        domain_input = input("\nEnter domain name: ")

        try:
            target_ip = socket.gethostbyname(domain_input) # Resolves IP from domain name
            domain_valid = True
            print(f"\nDomain resolved to IP: {target_ip}")
            start_port, end_port = port_selection() # Gets start and end ports
            scan_ports(target_ip, start_port, end_port)  # Calls port scan function, passing start and end ports

        except socket.gaierror:
            print("Invalid domain, please try again...")

def scan_ports(target_ip, start_port=1, end_port=1024): # Function for creating thread pool and calling port scanning function on each thread. Accepts start and end port for default scan
    open_ports = [] # List to store open ports
    start_time = time.time() # Records start time of scan

    print("\nScanning ports... \n")

    with ThreadPoolExecutor(max_workers=100) as executor: # Creates thread pool, scans a maximum of 100 ports at any given time
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, target_ip, port, open_ports)

    end_time = time.time() # Records end time of scan
    duration = end_time - start_time # Resolves duration of scan

    if open_ports:
        open_ports.sort()

        print("Open Ports Found:")
        for port in open_ports:
            print("-", port)

        print(f"Scan completed in {duration:.2f} seconds.")

        # Ask to save
        while True:
            save_choice = input("\nWould you like to save the results? (y/n): ").lower()
            if save_choice == "y":
                save_results(target_ip, open_ports, start_port, end_port, duration)
                break
            elif save_choice == "n":
                break
            else:
                print("Please enter 'y' or 'n'.")

    else: # If no ports are found print
        print("No Open Ports Found!")
        print(f"Scan completed in {duration:.2f} seconds.")



def scan_port(target_ip, port, open_ports): # Function for threads to create connections to ports
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Creates socket
    sock.settimeout(0.5) # Sets timeout to 0.5 seconds

    try:
        sock.connect((target_ip, port)) # Connects to user defined IP and port
        open_ports.append(port) # If connection is accepted it adds the port number to the list
    except OSError:
        pass
    finally:
        sock.close() # Closes socket regardless of success or failure


def save_results(target_ip, open_ports, start_port, end_port, duration):
    filename = f"hopescan_{target_ip.replace('.', '_')}.json"

    data = {
        "target": target_ip,
        "port_range": {
            "start": start_port,
            "end": end_port
        },
        "open_ports": sorted(open_ports),
        "scan_duration_seconds": round(duration, 2)
    }

    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

    print(f"Results saved to {filename}")

menu()