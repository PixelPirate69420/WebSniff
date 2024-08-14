import socket
import requests
import ssl
import json
import os
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import dns.resolver
import time
import random

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Well-known ports dictionary (reduced for brevity)
well_known_ports = {
    1: "TCPMUX (TCP Port Service Multiplexer)",
    2: "Management Utility",
    3: "Compression Process",
    4: "Unassigned",
    5: "Remote Job Entry",
    6: "Unassigned",
    7: "Echo Protocol",
    9: "Discard Protocol",
    11: "Active Users",
    13: "Daytime Protocol",
    17: "Quote of the Day",
    18: "Message Send Protocol",
    19: "Character Generator Protocol",
    20: "FTP (File Transfer Protocol) - data",
    21: "FTP (File Transfer Protocol) - control",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer Protocol)",
    26: "RSFTP (Restricted Simple File Transfer Protocol)",
    37: "Time Protocol",
    38: "Route Access Protocol",
    39: "Resource Location Protocol",
    42: "Host Name Server Protocol",
    43: "WHOIS Protocol",
    49: "TACACS Login Host Protocol",
    50: "Remote Mail Checking Protocol",
    53: "DNS (Domain Name System)",
    67: "DHCP (Dynamic Host Configuration Protocol) - server",
    68: "DHCP (Dynamic Host Configuration Protocol) - client",
    69: "TFTP (Trivial File Transfer Protocol)",
    70: "Gopher Protocol",
    79: "Finger Protocol",
    80: "HTTP (Hypertext Transfer Protocol)",
    88: "Kerberos Authentication",
    102: "MS Exchange Routing",
    110: "POP3 (Post Office Protocol version 3)",
    113: "Ident Protocol",
    119: "NNTP (Network News Transfer Protocol)",
    123: "NTP (Network Time Protocol)",
    135: "RPC (Remote Procedure Call)",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access Protocol)",
    161: "SNMP (Simple Network Management Protocol)",
    179: "BGP (Border Gateway Protocol)",
    194: "IRC (Internet Relay Chat)",
    207: "AppleTalk Time Server",
    2082: "cPanel (HTTP)",
    2083: "cPanel Secure (HTTPS)",
    2086: "WHM (Web Host Manager)",
    2087: "WHM Secure (HTTPS)",
    2095: "Webmail (HTTP)",
    2096: "Webmail Secure (HTTPS)",
    3306: "MySQL Database System",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL Database System",
    5433: "PostgreSQL Database System (TLS/SSL)",
    5500: "VNC Remote Frame Buffer Protocol",
    5900: "VNC (Virtual Network Computing)",
    5984: "CouchDB Database System",
    6379: "Redis Database",
    8080: "Apache Tomcat (HTTP)",
    8443: "Apache Tomcat (HTTPS)",
    9090: "WebSphere Application Server",
    9100: "Raw Printer Port",
    10000: "Network Data Management Protocol (NDMP)",
    11211: "Memcached",
    1521: "Oracle Database",
    2049: "NFS (Network File System)",
    27017: "MongoDB Database System",
    27018: "MongoDB Shard Cluster",
    28017: "MongoDB HTTP Interface",
    31337: "Back Orifice Remote Administration Tool",
    33060: "MySQL Database System (X Protocol)",
    3310: "Kerberos (Password Server)",
    389: "LDAP (Lightweight Directory Access Protocol)",
    443: "HTTPS (HTTP Secure)",
    465: "SMTPS (SMTP Secure)",
    5000: "MongoDB Database System (Sharding)",
    5001: "MongoDB Database System (SSL)",
    5439: "Amazon Redshift",
    6000: "X11 (X Window System)",
    6666: "IRC (Internet Relay Chat) (Alternate)",
    6667: "IRC (Internet Relay Chat) (Standard)",
    7000: "Font Service",
    7778: "Intergraph Software Services",
    7777: "Oracle Web Listener",
    8888: "HTTP (Alternative)",
    10001: "Multiple Arcade Machine Emulator (MAME)",
    11371: "OpenPGP HTTP Keyserver",
    15118: "Bordeaux Phosphor",
    16161: "Solaris Auditing",
    17001: "Lattice's Windows98 Run",
    20000: "DNP",
    21025: "Starbound Server Query",
    22136: "FLIR Systems Camera Streaming",
    22273: "Kali Linux",
    22600: "Mondrian Data Integration",
    24444: "NetBeans",
    27374: "Sub7",
    28201: "TorGuard Proxy",
    30005: "I3 Window Manager (X)",
    30718: "Xymon",
    31337: "Back Orifice",
    32976: "LogMeIn Hamachi (VPN Tunnel)",
    33434: "traceroute",
    37777: "Dahua DVR",
    44818: "EtherNet/IP Implicit Messaging",
    46824: "Ableton Link",
    47001: "Windows Remote Management (WinRM)",
    49152: "Windows Server (Windows dynamic/private ports)",
    49153: "Windows Server (Windows dynamic/private ports)",
    49154: "Windows Server (Windows dynamic/private ports)",
    49155: "Windows Server (Windows dynamic/private ports)",
    49156: "Windows Server (Windows dynamic/private ports)",
    49157: "Windows Server (Windows dynamic/private ports)",
}

# Function to get the IP address of a URL
def get_ip(url):
    domain = urlparse(url).netloc
    ip = socket.gethostbyname(domain)
    print(f"IP Address: {ip}")
    return {"IP Address": {"domain": domain, "ip": ip}}

# Function to get DNS A record
def get_dns(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        ip_addresses = [ip.address for ip in result]
        print(f"DNS A Record for {domain}: {ip_addresses}")
        return {"DNS A Record": {"domain": domain, "ip_addresses": ip_addresses}}
    except Exception as e:
        print(f"Error resolving DNS for {domain}: {e}")
        return {"DNS A Record": {"domain": domain, "error": str(e)}}

# Function to get the domain extension
def get_extension(url):
    domain = urlparse(url).netloc
    extension = domain.split('.')[-1]
    print(f"Domain Extension for {url}: {extension}")
    return {"Domain Extension": {"url": url, "extension": extension}}

# Function to scan common ports (TCP SYN scan)
def scan_ports(ip):
    open_ports = []
    closed_ports = []
    for port in well_known_ports.keys():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        else:
            closed_ports.append(port)
        sock.close()
    print(f"Open Ports: {open_ports}")
    print(f"Closed/Filtered Ports: {closed_ports}")
    return {"Port Scan": {"ip": ip, "open_ports": open_ports, "closed_ports": closed_ports}}

# Function to get HTTP/HTTPS headers
def get_headers(domain, protocol='http'):
    url = f"{protocol}://{domain}"
    response = requests.head(url, headers={"User-Agent": user_agent})
    headers = dict(response.headers)
    print(f"Headers for {url}:\n{headers}")
    return {f"{protocol.upper()} Headers": {"url": url, "headers": headers}}

# Function to get the size of the main page
def get_page_size(url):
    response = requests.get(url, headers={"User-Agent": user_agent})
    page_size = len(response.content)
    print(f"Size of {url}: {page_size} bytes")
    return {"Page Size": {"url": url, "size": page_size}}

def ping_website_and_port(url, port, duration):
    # Initialize list to store response times
    response_times = []

    # Calculate end time
    end_time = time.time() + duration

    # Ping loop
    while time.time() < end_time:
        try:
            start_time = time.time()
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)  # Set timeout for 1 second

            # Connect to server
            sock.connect((url, port))

            # Measure response time
            response_time = (time.time() - start_time) * 1000  # in milliseconds

            # Append response time to list
            response_times.append(response_time)

            # Close socket
            sock.close()

            # Print response time
            print(f"Response time: {response_time:.2f} ms")

        except socket.error as e:
            print(f"Failed to connect to {url}:{port} - {e}")

        # Sleep for 1 second before pinging again
        time.sleep(1)

    # Print summary
    print("\nPing Summary:")
    print(f"Total pings recorded: {len(response_times)}")
    if len(response_times) > 0:
        min_time = min(response_times)
        max_time = max(response_times)
        avg_time = sum(response_times) / len(response_times)
        print(f"Minimum response time: {min_time:.2f} ms")
        print(f"Maximum response time: {max_time:.2f} ms")
        print(f"Average response time: {avg_time:.2f} ms")

    # Return response times list
    return response_times
# Function to get DNS records
def get_dns_records(domain):
    records = {}
    for record_type in [
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT', 'CAA',  # Common record types
    'DNSKEY', 'DS', 'NAPTR', 'TLSA', 'SPF', 'SSHFP', 'LOC',  # Additional standard record types
    'PTR', 'HINFO', 'AFSDB', 'CERT', 'DNAME', 'KEY', 'NSEC', 'RRSIG', 'RP', 'SIG', 'TKEY', 'TSIG',  # Less common or historic record types
    'HIP', 'NID', 'NINFO', 'RKEY', 'APL', 'CDNSKEY', 'CDS', 'CSYNC', 'DHCID', 'DLV', 'EUI48', 'EUI64', 'GPOS', 'KX', 'L32', 'L64', 'LP', 'MB', 'MD', 'MF', 'MG', 'MINFO', 'MR', 'MX', 'NSEC3', 'NSEC3PARAM', 'NSAP', 'NSAP-PTR', 'PX', 'SINK', 'SMIMEA', 'TA', 'TALINK', 'URI', 'WKS', 'X25']:
        try:
            result = dns.resolver.resolve(domain, record_type)
            records[record_type] = [rdata.to_text() for rdata in result]
        except dns.resolver.NoAnswer:
            records[record_type] = []
        except Exception as e:
            print(f"Error retrieving {record_type} records for {domain}: {e}")
    print(f"DNS Records for {domain}:\n{records}")
    return {"DNS Records": {"domain": domain, "records": records}}

# Function to get SSL/TLS information
def get_ssl_info(domain):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
    print(f"SSL/TLS Information for {domain}:\n{cert}")
    return {"SSL/TLS Information": {"domain": domain, "certificate": cert}}

# Function to get files loaded by the main page
def get_loaded_files(url):
    response = requests.get(url, headers={"User-Agent": user_agent})
    soup = BeautifulSoup(response.content, 'html.parser')
    loaded_files = [tag['src'] for tag in soup.find_all('script', src=True)] + \
                   [tag['href'] for tag in soup.find_all('link', href=True)]
    print(f"Files loaded by {url}:\n{loaded_files}")
    return {"Loaded Files": {"url": url, "files": loaded_files}}

# Function to send random data to a port and check response
def send_random_data(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            sock.sendall(b'GET / HTTP/1.1\r\n\r\n')
            response = sock.recv(4096)
        response_text = response.decode('utf-8', errors='ignore')
        print(f"Response from {ip}:{port} for random data:\n{response_text}")
        return {f"Random Data Response {port}": {"ip": ip, "response": response_text}}
    except Exception as e:
        print(f"Error sending random data to {ip}:{port}: {e}")
        return {f"Random Data Response {port}": {"ip": ip, "error": str(e)}}

def ping_website_and_port(url, port, duration):
    # Initialize list to store response times
    response_times = []

    # Calculate end time
    end_time = time.time() + duration

    # Ping loop
    while time.time() < end_time:
        try:
            start_time = time.time()
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)  # Set timeout for 1 second

            # Connect to server
            sock.connect((url, port))

            # Measure response time
            response_time = (time.time() - start_time) * 1000  # in milliseconds

            # Append response time to list
            response_times.append(response_time)

            # Close socket
            sock.close()

            # Print response time
            print(f"Response time: {response_time:.2f} ms")

        except socket.error as e:
            print(f"Failed to connect to {url}:{port} - {e}")

        # Sleep for 1 second before pinging again
        time.sleep(1)

    # Print summary
    print("\nPing Summary:")
    print(f"Total pings recorded: {len(response_times)}")
    if len(response_times) > 0:
        min_time = min(response_times)
        max_time = max(response_times)
        avg_time = sum(response_times) / len(response_times)
        print(f"Minimum response time: {min_time:.2f} ms")
        print(f"Maximum response time: {max_time:.2f} ms")
        print(f"Average response time: {avg_time:.2f} ms")

    # Return response times list
    return response_times

# Function for TCP SYN scan on well-known ports
def tcp_syn_scan(ip):
    def create_matrix(input_list, dictionary):
        matrix = [[item, dictionary.get(item, None)] for item in input_list]
        return matrix

    open_ports = []
    closed_ports = []
    for port in well_known_ports.keys():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        else:
            closed_ports.append(port)
        sock.close()
    print(f"TCP SYN Scan - Open Ports: {open_ports}")
    print(f"TCP SYN Scan - Closed/Filtered Ports: {closed_ports}")
    return {"TCP SYN Scan": {"ip": ip, "open_ports": create_matrix(open_ports, well_known_ports), "closed_ports": create_matrix(closed_ports, well_known_ports)}}


# Function for brute force TCP SYN scan on all ports
def brute_force_scan(ip):
    def brute_matrix(input_list, dictionary):
        matrix = [[item, dictionary.get(item, "service unknown")] for item in input_list]
        return matrix
    open_ports = []
    closed_ports = []
    for port in range(1, 65536):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        else:
            closed_ports.append(port)
        sock.close()
    print(f"Brute Force TCP SYN Scan - Open Ports: {open_ports}")
    print(f"Brute Force TCP SYN Scan - Closed/Filtered Ports: {closed_ports}")
    return {"Brute Force TCP SYN Scan": {"ip": ip, "open_ports": brute_matrix(open_ports, well_known_ports), "closed_ports": brute_matrix(closed_ports, well_known_ports)}}

# Function to connect and capture conversation on open ports
def connect_and_capture(ip, open_ports):
    captured_data = {}
    for protocol, port in open_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((ip, port))
            if protocol == 'http':
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {user_agent}\r\n\r\n"
            elif protocol == 'https':
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {user_agent}\r\n\r\n"
            else:
                request = f"\r\n\r\n"
            sock.sendall(request.encode('utf-8'))

            # Receiving and decoding response
            response = sock.recv(4096)
            response_text = response.decode('utf-8', errors='ignore')

            captured_data[port] = response_text
            print(f"Captured data from port {port}:\n{response_text}\n")
        except Exception as e:
            print(f"Error capturing data from port {port}: {e}")
        finally:
            sock.close()
    return {"Captured Conversations": {"ip": ip, "data": captured_data}}

def save_to_json(data, filename):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            try:
                existing_data = json.load(file)
                if isinstance(existing_data, list):
                    existing_data.append(data)
                elif isinstance(existing_data, dict):
                    existing_data.update(data)
                else:
                    existing_data = [existing_data, data]
            except json.JSONDecodeError:
                existing_data = [data]
    else:
        existing_data = [data]

    with open(filename, 'w') as file:
        json.dump(existing_data, file, indent=4)

def fetch_website(url, port=None, method='GET', headers={}, payload=None, proxy_host=None, proxy_port=None, timeout=10, include_content_length=True, http_version='HTTP/1.1'):
    try:
        # Parse the URL to extract scheme, host, and path
        parsed_url = urlparse(url)
        scheme = parsed_url.scheme
        host = parsed_url.netloc
        path = parsed_url.path if parsed_url.path else '/'

        # Determine the default port if not provided
        if port is None:
            port = 443 if scheme == 'https' else 80

        # Create a socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(timeout)  # Set the timeout for the socket

        if proxy_host and proxy_port:
            # Connect to the proxy server
            client_socket.connect((proxy_host, proxy_port))
            connect_command = f"CONNECT {host}:{port} {http_version}\r\n"
            connect_command += f"Host: {host}:{port}\r\n"
            connect_command += "Connection: close\r\n\r\n"
            client_socket.sendall(connect_command.encode())

            # Receive the proxy's response to the CONNECT command
            response = b""
            while True:
                data = client_socket.recv(4096)
                if not data or b"\r\n\r\n" in data:
                    response += data
                    break
                response += data

            # Check if the proxy connection was successful
            if b"200 Connection established" not in response:
                print(f"Failed to connect to proxy {proxy_host}:{proxy_port}")
                return None

        if scheme == 'https':
            context = ssl.create_default_context()
            ssl_socket = context.wrap_socket(client_socket, server_hostname=host)
        else:
            ssl_socket = client_socket

        if not proxy_host:
            # Connect to the server (website) directly
            ssl_socket.connect((host, port))

        # Construct the HTTP request
        request_headers = f"{method} {path} {http_version}\r\n"
        request_headers += f"Host: {host}\r\n"
        for key, value in headers.items():
            request_headers += f"{key}: {value}\r\n"

        # Add Content-Length header if include_content_length is True and there is a payload
        if payload:
            payload_str = payload if isinstance(payload, str) else str(payload)
            if include_content_length:
                request_headers += f"Content-Length: {len(payload_str)}\r\n"

        request_headers += "Connection: close\r\n\r\n"

        # Send the request headers
        ssl_socket.sendall(request_headers.encode())

        # Send the payload if there is one
        if payload:
            ssl_socket.sendall(payload_str.encode())

        # Receive the response
        response = b""
        while True:
            data = ssl_socket.recv(4096)
            if not data:
                break
            response += data

        # Close the socket
        ssl_socket.close()

        try:
            # Return the decoded response content
            return response.decode('utf-8')
        except UnicodeDecodeError:
            # Return the raw bytes if decoding fails
            return response

    except ssl.SSLError as ssl_error:
        print(f"SSL error fetching {url}: {ssl_error}")
        return None
    except socket.timeout:
        print(f"Timeout occurred while fetching {url}")
        return None
    except socket.error as sock_error:
        print(f"Socket error fetching {url}: {sock_error}")
        return None
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

# General scan function encompassing all steps
def general_scan(url):
    domain = urlparse(url).netloc
    ip_info = get_ip(url)
    dns_info = get_dns(domain)
    extension_info = get_extension(url)
    #port_scan_info = scan_ports(ip_info["IP Address"]["ip"])
    headers_info_http = get_headers(domain, 'http')
    headers_info_https = get_headers(domain, 'https')
    page_size_info = get_page_size(url)
    dns_records_info = get_dns_records(domain)
    ssl_info = get_ssl_info(domain)
    loaded_files_info = get_loaded_files(url)
    random_data_http = send_random_data(ip_info["IP Address"]["ip"], 80)
    random_data_https = send_random_data(ip_info["IP Address"]["ip"], 443)
    tcp_syn_scan_info = tcp_syn_scan(ip_info["IP Address"]["ip"])

    combined_data = {
        "IP Information": ip_info,
        "DNS Information": dns_info,
        "Domain Extension": extension_info,
        #"Port Scan": port_scan_info,
        "HTTP Headers": headers_info_http,
        "HTTPS Headers": headers_info_https,
        "Page Size": page_size_info,
        "DNS Records": dns_records_info,
        "SSL/TLS Information": ssl_info,
        "Loaded Files": loaded_files_info,
        "Random Data HTTP": random_data_http,
        "Random Data HTTPS": random_data_https,
        "TCP SYN Scan": tcp_syn_scan_info
    }

    save_choice = input("Do you want to save the general scan data to a JSON file? (yes/no): ").strip().lower()
    if save_choice in ("yes", "y"):
        filename = input("Enter a filename to save general scan data (without extension): ").strip()
        filename += ".json"
        save_to_json(combined_data, filename)

# Main menu
def main():
    while True:
        print("\nWebSniff Menu:\n")

        print("{:<30} {:<30}".format("Website Data:", "Network Sniffing:"))
        print("{:<30} {:<30}".format(" 1.  Get IP Address", "11.  Send Random Data to Port"))
        print("{:<30} {:<30}".format(" 2.  Get DNS A Record", "12.  Perform TCP SYN Scan"))
        print("{:<30} {:<30}".format(" 3.  Get Domain Extension", "13.  Perform Brute Force TCP SYN Scan"))
        print("{:<30} {:<30}".format(" 4.  Scan Common Ports", "14.  Connect and Capture Data (HTTP/HTTPS)"))
        print("{:<30} {:<30}".format(" 5.  Get HTTP Headers", "17.  Ping Capture on Port"))
        print("{:<30} {:<30}".format(" 6.  Get HTTPS Headers", ""))
        print("{:<30} {:<30}".format(" 7.  Get Page Size", "Error Sniffing:"))
        print("{:<30} {:<30}".format(" 8.  Get DNS Records", "18.  ---------"))
        print("{:<30} {:<30}".format(" 9.  Get SSL/TLS Information", "19.  Error 400 Scenario"))
        print("{:<30} {:<30}".format("10.  Get Loaded Files", "20.  Error 404 Scenario"))

        print("{:<30} {:<30}".format("", "21.  Error 405 Scenario"))
        print("{:<30} {:<30}".format("", "22.  Error 406 Scenario"))
        print("{:<30} {:<30}".format("", "23.  Error 407 Scenario"))
        print("{:<30} {:<30}".format("", "24.  Error 408 Scenario"))
        print("{:<30} {:<30}".format("", "25.  Error 409 Scenario"))
        print("{:<30} {:<30}".format("", "26.  Error 411 Scenario"))
        print("{:<30} {:<30}".format("", "27.  Error 412 Scenario"))
        print("{:<30} {:<30}".format("", "28.  Error 413 Scenario"))
        print("{:<30} {:<30}".format("", "29.  Error 414 Scenario"))
        print("{:<30} {:<30}".format("", "30.  Error 415 Scenario"))
        print("{:<30} {:<30}".format("", "31.  Error 416 Scenario"))
        print("{:<30} {:<30}".format("", "32.  Error 417 Scenario"))
        print("{:<30} {:<30}".format("", "33.  Error 421 Scenario"))
        print("{:<30} {:<30}".format("", "34.  Error 422 Scenario"))
        print("{:<30} {:<30}".format("", "35.  Error 424 Scenario"))
        print("{:<30} {:<30}".format("", "36.  Error 425 Scenario"))
        print("{:<30} {:<30}".format("", "37.  Error 426 Scenario"))
        print("{:<30} {:<30}".format("", "38.  Error 428 Scenario"))
        print("{:<30} {:<30}".format("", "39.  Error 431 Scenario"))
        print("{:<30} {:<30}".format("", "40.  Error 451 Scenario"))
        print("{:<30} {:<30}".format("", "41.  Error 505 Scenario"))


        print("{:<30} {:<30}".format("Automatic:", ""))
        print("{:<30} {:<30}".format("15.  Perform General Scan", ""))
        print("{:<30} {:<30}".format("16.  Exit", ""))
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            url = input("Enter the URL: ").strip()
            ip_info = get_ip(url)
            save_choice = input("Do you want to save the IP information to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save IP information (without extension): ").strip()
                filename += ".json"
                save_to_json(ip_info, filename)
        elif choice == '2':
            domain = input("Enter the domain: ").strip()
            dns_info = get_dns(domain)
            save_choice = input("Do you want to save the DNS A record information to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save DNS A record information (without extension): ").strip()
                filename += ".json"
                save_to_json(dns_info, filename)
        elif choice == '3':
            url = input("Enter the URL: ").strip()
            extension_info = get_extension(url)
            save_choice = input("Do you want to save the domain extension information to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save domain extension information (without extension): ").strip()
                filename += ".json"
                save_to_json(extension_info, filename)
        elif choice == '4':
            ip = input("Enter the IP address: ").strip()
            port_scan_info = scan_ports(ip)
            save_choice = input("Do you want to save the port scan information to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save port scan information (without extension): ").strip()
                filename += ".json"
                save_to_json(port_scan_info, filename)
        elif choice == '5':
            domain = input("Enter the domain: ").strip()
            headers_info_http = get_headers(domain, 'http')
            save_choice = input("Do you want to save the HTTP headers information to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save HTTP headers information (without extension): ").strip()
                filename += ".json"
                save_to_json(headers_info_http, filename)
        elif choice == '6':
            domain = input("Enter the domain: ").strip()
            headers_info_https = get_headers(domain, 'https')
            save_choice = input("Do you want to save the HTTPS headers information to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save HTTPS headers information (without extension): ").strip()
                filename += ".json"
                save_to_json(headers_info_https, filename)
        elif choice == '7':
            url = input("Enter the URL: ").strip()
            page_size_info = get_page_size(url)
            save_choice = input("Do you want to save the page size information to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save page size information (without extension): ").strip()
                filename += ".json"
                save_to_json(page_size_info, filename)
        elif choice == '8':
            domain = input("Enter the domain: ").strip()
            dns_records_info = get_dns_records(domain)
            save_choice = input("Do you want to save the DNS records information to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save DNS records information (without extension): ").strip()
                filename += ".json"
                save_to_json(dns_records_info, filename)
        elif choice == '9':
            domain = input("Enter the domain: ").strip()
            ssl_info = get_ssl_info(domain)
            save_choice = input("Do you want to save the SSL/TLS information to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save SSL/TLS information (without extension): ").strip()
                filename += ".json"
                save_to_json(ssl_info, filename)
        elif choice == '10':
            url = input("Enter the URL: ").strip()
            loaded_files_info = get_loaded_files(url)
            save_choice = input("Do you want to save the loaded files information to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save loaded files information (without extension): ").strip()
                filename += ".json"
                save_to_json(loaded_files_info, filename)
        elif choice == '11':
            ip = input("Enter the IP address: ").strip()
            port = int(input("Enter the port number: ").strip())
            random_data_info = send_random_data(ip, port)
            save_choice = input("Do you want to save the random data response to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save random data response (without extension): ").strip()
                filename += ".json"
                save_to_json(random_data_info, filename)
        elif choice == '12':
            ip = input("Enter the IP address: ").strip()
            tcp_syn_scan_info = tcp_syn_scan(ip)
            save_choice = input("Do you want to save the TCP SYN scan data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save TCP SYN scan data (without extension): ").strip()
                filename += ".json"
                save_to_json(tcp_syn_scan_info, filename)
        elif choice == '13':
            ip = input("Enter the IP address: ").strip()
            brute_force_scan_info = brute_force_scan(ip)
            save_choice = input("Do you want to save the brute force scan data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save brute force scan data (without extension): ").strip()
                filename += ".json"
                save_to_json(brute_force_scan_info, filename)
        elif choice == '14':
            def format_http_response(response_str):
                lines = response_str.strip().split('\r\n')
                formatted_response = '\n'.join(lines)
                return f'"Conversation captured": {{\n{formatted_response}\n}}'

            print("What to expect from this function?\nThis function does a 'GET' request\nto the website and port you chose\nand it captures the talk between you and the website.")
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            method = 'GET'
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            captured_data_info = fetch_website(url, port, method, headers)
            print(captured_data_info)
            combined_data = {f"Captured GET protocol at: {port}" : captured_data_info}
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json(combined_data, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")
        elif choice == '15':
            url = input("Enter the URL: ").strip()
            general_scan(url)
        elif choice == '16':
            print("Exiting WebSniff. Goodbye!")
            break
        elif choice == '17':
            url = input("Enter the IP Address: ").strip()
            port = int(input("Enter the port: ").strip())
            duration = float(input("Enter the duration in seconds: ").strip())
            combined_data = {f"Ping Capture at: {url} on port: {port} duration: {duration} seconds" : ping_website_and_port(url, port, duration)}
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json(combined_data, filename)

        elif choice == '19':
            def generate_random_number():
                #Step 1: Randomly choose the number of digits between 1 and 16
                num_digits = random.randint(1, 16)

                # Step 2: Calculate the range for the chosen number of digits
                min_value = 10**(num_digits - 1)
                max_value = 10**num_digits - 1

                # Step 3: Generate a random number within the calculated range
                random_number = random.randint(min_value, max_value)
                return random_number

            responses = []
            def format_http_response(response_str):
                lines = response_str.strip().split('\r\n')
                formatted_response = '\n'.join(lines)
                return f'"Error 400 scenario on port {port}": {{\n{formatted_response}\n}}'

            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            method = 'INVALID_METHOD'
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            captured_data_info = fetch_website(url, port, method='INVALID-METHOD', headers=headers, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Using an INVALID-METHOD" : captured_data_info}
            responses.append(combined_data)

            captured_data_info = fetch_website(url, port, method='GET', headers={"Content-Type": "application/json"}, payload="{invalid_json: true}", proxy_host=None, proxy_port=None)
            combined_data = {f"Using a MALFORMED PAYLOAD" : captured_data_info}
            responses.append(combined_data)

            captured_data_info = fetch_website(url, port, method=f'{generate_random_number()}', headers={"Content-Type": "application/json"}, payload="{invalid_json: true}", proxy_host=None, proxy_port=None)
            combined_data = {f"Using a RANDOM NUMBER as REQUEST" : captured_data_info}
            responses.append(combined_data)

            captured_data_info = fetch_website(url, port, method=f'GET', headers={'Accept': 'text/html', 'Invalid Header': 'no colon'}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Using an INVALID-HEADER" : captured_data_info}
            responses.append(combined_data)
            print(responses)

            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 400 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '20':
            def generate_random_number():
                # Step 1: Randomly choose the number of digits between 1 and 16
                num_digits = random.randint(1, 16)

                # Step 2: Calculate the range for the chosen number of digits
                min_value = 10**(num_digits - 1)
                max_value = 10**num_digits - 1

                # Step 3: Generate a random number within the calculated range
                random_number = random.randint(min_value, max_value)
                return random_number

            def format_http_response(response_str):
                lines = response_str.strip().split('\r\n')
                formatted_response = '\n'.join(lines)
                return f'"Error 404 scenario on port {port}": {{\n{formatted_response}\n}}'

            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            method = 'INVALID_METHOD'
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            captured_data_info = fetch_website(f"{url}/path/to/nonexistent/%%%{generate_random_number()}", port, method='GET', headers={}, payload=None, proxy_host=None, proxy_port=None)
            print(captured_data_info)
            combined_data = {f"Error 404 scenario on port {port}: {port}" : captured_data_info}
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json(combined_data, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")
        elif choice == '21':
            responses = []
            requests = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            for i in range(len(requests)):
                captured_data_info = fetch_website(url, port, method=requests[i], headers=headers, payload=None, proxy_host=None, proxy_port=None)
                combined_data = {f"Using a {requests[i]} METHOD" : str(captured_data_info)}
                responses.append(combined_data)
            print(responses)
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 405 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")
        elif choice == '22':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            captured_data_info = fetch_website(url, port, method='GET', headers={'Accept': 'application/x-unreal-format'}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Using an INVALID-ACCEPT-HEADER" : str(captured_data_info)}
            responses.append(combined_data)

            captured_data_info = fetch_website(url, port, method='GET', headers={'Accept-Charset': 'ISO-8859-5'}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Using an INVALID-CHARSET-HEADER" : str(captured_data_info)}
            responses.append(combined_data)

            captured_data_info = fetch_website(url, port, method='GET', headers={'Accept-Encoding': 'compress, gzip, br, non-existent'}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Using an INVALID-COMPRESSION-HEADER" : str(captured_data_info)}
            responses.append(combined_data)

            captured_data_info = fetch_website(url, port, method='GET', headers={'Accept-Language': 'non-existent'}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Using an INVALID-LANGUAGE-HEADER" : str(captured_data_info)}
            responses.append(combined_data)

            captured_data_info = fetch_website(url, port, method='POST', headers={'Accept': 'application/json'}, payload='<xml></xml>', proxy_host=None, proxy_port=None)
            combined_data = {f"Using an INVALID-LANGUAGE-HEADER" : str(captured_data_info)}
            responses.append(combined_data)

            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 405 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '23':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())

            captured_data_info = fetch_website(url, port, method='GET', headers={}, payload=None, proxy_host="proxy.example.com", proxy_port=8080)
            combined_data = {f"Missing Proxy Authentication Credentials" : str(captured_data_info)}
            responses.append(combined_data)

            captured_data_info = fetch_website(url, port, method='GET', headers={"Proxy-Authorization": "invalid-proxy-token"}, payload=None, proxy_host="proxy.example.com", proxy_port=8080)
            combined_data = {f"Invalid Proxy Authentication Credentials" : str(captured_data_info)}
            responses.append(combined_data)

            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 407 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '24':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port=None, method='GET', headers=headers, payload=None, proxy_host=None, proxy_port=None, timeout=0.001)
            combined_data = {f"Server Not Receiving Complete Request in Time" : str(captured_data_info)}
            responses.append(combined_data)

            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 408 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '25':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='POST', headers=headers, payload={"conflict": "data"}, proxy_host=None, proxy_port=None)
            combined_data = {f"Conflict with Current State of Resource" : str(captured_data_info)}
            responses.append(combined_data)
            print(responses)

            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 409 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '26':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='POST', headers=headers, payload="data", proxy_host=None, proxy_port=None, include_content_length=False)
            combined_data = {f"No Content-Length Header with Payload" : str(captured_data_info)}
            responses.append(combined_data)

            captured_data_info = fetch_website(url, port, method='POST', headers={"Content-Length": ""}, payload="data", proxy_host=None, proxy_port=None, include_content_length=True)
            combined_data = {f"Explicitly Empty Content-Length Header" : str(captured_data_info)}
            responses.append(combined_data)

            captured_data_info = fetch_website(url, port, method='PUT', headers=headers, payload="data", proxy_host=None, proxy_port=None, include_content_length=False)
            combined_data = {f"Missing Content-Length for a Method Requiring It" : str(captured_data_info)}
            responses.append(combined_data)

            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 411 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '27':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='GET', headers={"If-Match": "invalid-etag"}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Failed Precondition in Header" : str(captured_data_info)}
            responses.append(combined_data)

            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 412 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '28':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='POST', headers=headers, payload="x" * 10**7, proxy_host=None, proxy_port=None)
            combined_data = {f"Excessively Large Payload" : str(captured_data_info)}
            responses.append(combined_data)
            print(responses)

            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 413 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '29':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url + "/" + "a" * 20000, port, method='GET', headers=headers, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"URL Too Long" : str(captured_data_info)}
            responses.append(combined_data)
            print(responses)

            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 414 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '30':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port=None, method='PUT', headers={"Content-Type": "application/unsupported"}, payload="data", proxy_host=None, proxy_port=None)
            combined_data = {f"Unsupported Media Type (method: PUT)" : str(captured_data_info)}
            responses.append(combined_data)

            captured_data_info = fetch_website(url, port=None, method='POST', headers={"Content-Type": "application/unsupported"}, payload="data", proxy_host=None, proxy_port=None)
            combined_data = {f"Unsupported Media Type (method: POST)" : str(captured_data_info)}
            responses.append(combined_data)

            print(responses)

            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 415 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '31':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='GET', headers={"Range": "bytes=1000-2000"}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Invalid Range Request" : str(captured_data_info)}
            responses.append(combined_data)

            print(responses)
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 416 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '32':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='GET', headers={"Expect": "100-continue"}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Unmet Expectation in Header" : str(captured_data_info)}
            responses.append(combined_data)

            print(responses)
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 417 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '33':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port=None, method='GET', headers={"Host": "wronghost"}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Incorrect Host Header" : str(captured_data_info)}
            responses.append(combined_data)

            print(responses)
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 421 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '34':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='POST', headers={"Content-Type": "application/json"}, payload="{invalid: json}", proxy_host=None, proxy_port=None)
            combined_data = {f"Malformed JSON Payload" : str(captured_data_info)}
            responses.append(combined_data)

            print(responses)
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 422 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '35':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='GET', headers={"Depend": "previous-failed"}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Dependent Request Fails" : str(captured_data_info)}
            responses.append(combined_data)

            print(responses)
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 424 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '36':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='POST', headers={"Early-Data": "1"}, payload="data", proxy_host=None, proxy_port=None)
            combined_data = {f"Early Data in Request" : str(captured_data_info)}
            responses.append(combined_data)

            print(responses)
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 425 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '37':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='GET', headers={"Upgrade": "TLS/1.0"}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Protocol Upgrade Required" : str(captured_data_info)}
            responses.append(combined_data)

            print(responses)
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 426 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '38':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='GET', headers={"If-None-Match": "*"}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Precondition Required in Request" : str(captured_data_info)}
            responses.append(combined_data)

            print(responses)
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 428 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '39':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='GET', headers={"Large-Header": "a" * 1000000000}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Excessively Large Headers" : str(captured_data_info)}
            responses.append(combined_data)

            print(responses)
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 431 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '40':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='GET', headers={"Legal-Restriction": "true"}, payload=None, proxy_host=None, proxy_port=None)
            combined_data = {f"Accessing Legally Restricted Resource" : str(captured_data_info)}
            responses.append(combined_data)

            print(responses)
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 451 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")

        elif choice == '41':
            responses = []
            url = input("Enter the URL: ").strip()
            port = eval(input("Enter the port: ").strip())
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

            captured_data_info = fetch_website(url, port, method='GET', headers=headers, payload=None, proxy_host=None, proxy_port=None, http_version='HTTP/0.1')
            combined_data = {f"Unsupported HTTP Version" : str(captured_data_info)}
            responses.append(combined_data)

            print(responses)
            save_choice = input("Do you want to save the captured data to a JSON file? (yes/no): ").strip().lower()
            if save_choice in ("yes", "y"):
                filename = input("Enter a filename to save captured data (without extension): ").strip()
                filename += ".json"
                save_to_json({f"Error 505 scenario on port {port}" : responses}, filename)
            else:
                print("Invalid input format for open ports. Please enter a list of tuples.")


        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
