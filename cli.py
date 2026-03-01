def menu():
    while True:
        print("\n--- HopeScan ---")
        print("1 - Basic Port Scan")
        print("2 - Service Enumeration Scan")
        print("3 - Exit")

        choice = input(">> ")

        if choice == "1":
            scan_type = "basic"
            target_menu(scan_type)

        elif choice == "2":
            scan_type = "enum"
            target_menu(scan_type)

        elif choice == "3":
            print("\nExiting HopeScan...")
            break

        else:
            print("Invalid option.")


def target_menu(scan_type):
    print("\n1 - Scan an IP Address")
    print("2 - Scan a Domain Name")

    target_choice = input(">> ")

    if target_choice == "1":
        ip(scan_type)
    elif target_choice == "2":
        dom(scan_type)
    else:
        print("Invalid option.")


def ip(scan_type): # Takes IP input
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
        scan_ports(target_ip, start_port, end_port, scan_type)  # Calls port scan function, passing start and end ports


def dom(scan_type):
    domain_valid = False

    while not domain_valid:
        domain_input = input("\nEnter domain name: ")

        try:
            target_ip = socket.gethostbyname(domain_input) # Resolves IP from domain name
            domain_valid = True
            print(f"\nDomain resolved to IP: {target_ip}")
            start_port, end_port = port_selection() # Gets start and end ports
            scan_ports(target_ip, start_port, end_port, scan_type)  # Calls port scan function, passing start and end ports

        except socket.gaierror:
            print("Invalid domain, please try again...")


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