import ipaddress
import socket
import time

def main():     # Main function for taking user input
    ip_valid = False

    while ip_valid == False: # Loop to validate IP Address input is correct
        target_ip = input("Enter target IP: ")

        try:
            ipaddress.IPv4Address(target_ip) # Valid IP
            ip_valid = True

        except ipaddress.AddressValueError: # Invalid IP
            ip_valid = False
            print("Invalid IP Address, please try again...")

    if ip_valid == True:
        scan_ports(target_ip)

def scan_ports(target_ip): # Function for port scanning
    open_ports = []
    start_time = time.time() # Records start time of scan

    print("Scanning ports...")

    for port in range(1, 1025): # Loops through port 1-1024
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Creates socket
        sock.settimeout(0.5) # Sets timeout to 0.5 seconds
        try:
            sock.connect((target_ip, port)) # Connects to user defined IP and port
            open_ports.append(port) # If connection is accepted it adds the port number to the list
        except OSError:
            pass
        finally:
            sock.close() # Closes socket regardless of success or failure

    end_time = time.time() # Records end time of scan
    duration = end_time - start_time # Resolves duration of scan

    if open_ports: # If open ports are found print results & scan duration
        print("Open Ports Found:")
        for port in open_ports:
            print("-", port)
        print(f"Scan completed in {duration:.2f} seconds.")
    else: # If no ports are found print
        print("No Open Ports Found!")
        print(f"Scan completed in {duration:.2f} seconds.")


main()