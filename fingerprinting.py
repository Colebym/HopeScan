import socket
import ssl

# Optional imports (won’t crash if not installed)
try:
    from impacket.smbconnection import SMBConnection
except:
    SMBConnection = None

try:
    import dns.resolver
except:
    dns = None

try:
    from ldap3 import Server
except:
    Server = None


def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))

        if port in [80, 8080]:
            s.send(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())

        if port == 443:
            context = ssl.create_default_context()
            with context.wrap_socket(s, server_hostname=ip) as ssock:
                ssock.send(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
                return ssock.recv(2048).decode(errors="ignore")

        banner = s.recv(2048)
        s.close()

        return banner.decode(errors="ignore")

    except:
        return None


def get_dns_version(ip):
    if not dns:
        return None

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        answer = resolver.resolve("version.bind", "TXT", tcp=True)

        for r in answer:
            return str(r)

    except:
        return None


def get_smb_version(ip):
    if not SMBConnection:
        return None

    try:
        conn = SMBConnection(ip, ip)
        conn.login('', '')
        os_info = conn.getServerOS()
        conn.close()
        return os_info
    except:
        return None


def get_ldap_info(ip):
    if not Server:
        return None

    try:
        server = Server(ip, get_info='ALL')
        return str(server.info)

    except:
        return None


