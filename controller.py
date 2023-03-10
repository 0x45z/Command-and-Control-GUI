import socket
import threading
import time
import sys
import ast


class ClientHandler(threading.Thread):
    def __init__(self, socket, address, buffer):
        threading.Thread.__init__(self)
        self.socket = socket
        self.address = address
        self.buffer = buffer

    def run(self):
        # Listen for messages from client

        while True:
            recv_len = 1
            message = ''
            while recv_len:
                data = self.socket.recv(self.buffer)  # receive data
                if not data:
                    # Client has disconnected
                    break
                recv_len = len(data)  # get the length of the data
                message += data.decode('utf-8')  # append the received data to message string
                if recv_len < self.buffer:  # if received data is less than buffer, all data is received
                    break
            if message:
                print(f"[+]{self.address} says:\n{message}")
            if not message:
                # Client has disconnected
                print(f'Client [{self.address}] Disconnected')
                server.remove_client(self.address)  # remove client from dict
                self.socket.close()  # close socket
                break  # break out of while loop

    def send(self, message):
        self.socket.sendall(message.encode('utf-8'))


class Server:
    def __init__(self, ip, port, buffer):
        self.ip = ip
        self.port = port
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # release socket after closed
        self.socket.bind((self.ip, self.port))
        self.clients = {}

    def listen(self):
        self.socket.listen(20)
        print("Listening...")

        try:
            while True:
                conn, address = self.socket.accept()
                print(f'Connection from {address}')
                client_thread = ClientHandler(conn, address, self.buffer)  # create a thread to handle individual client
                self.clients[address] = conn  # add the socket object to a dictionary with client address as key
                client_thread.start()
                print(f"Clients Connected: {len(self.clients)}")

        except KeyboardInterrupt:
            self.socket.close()
            sys.exit(0)

    def send_to_one(self, address, message):
        if address in self.clients:  # make sure client exists
            self.clients[address].send(message)  # send message using socket object
        else:
            print(f"Client {address} does not exist")

    def remove_client(self, client):
        del self.clients[client]


def one_to_one_mode():
    """
    send one command to one client
    """
    while True:
        try:
            command = input("1-1$ ")
            command = command.split(") ", 1)
            addr = command[0]
            if "exit" in addr:
                break
            message = command[1:]
            addr += ")"
            addr = ast.literal_eval(addr)  # turn string to tuple
            message = "".join(message)  # turn list to string
            message = bytes(message.encode('utf-8'))  # turn string to bytes
            server.send_to_one(addr, message)  # send to client
        except IndexError:
            print('Invalid input')
        except KeyboardInterrupt:
            sys.exit(0)
        except SyntaxError:
            # invalid input for ast.literal_eval so just pass
            pass


def many_to_one_mode():
    """
    Send multiple commands to one client
    """
    while True:
        try:
            command = input("m-1$ ")
            command = command.split(") ", 1)
            addr = command[0]
            if "exit" in addr:
                break
            commands = command[1:]
            commands = commands[0].split()
            addr += ")"
            addr = ast.literal_eval(addr)  # turn string to tuple
            for command in commands:
                server.send_to_one(addr, bytes(command.encode()))
                time.sleep(0.15)

        except IndexError:
            print('Invalid input')
        except KeyboardInterrupt:
            sys.exit(0)
        except SyntaxError:
            # invalid input for ast.literal_eval so just pass
            pass


def one_to_many_mode():
    """
    One command is sent to many machines
    """
    while True:
        try:
            command = input("1-m$ ")
            if "exit" in command:
                break
            command = command.split(") ")  # split at every closing bracket
            addresses = []
            instruction = ""
            for item in command:
                if item[0] == "(":
                    # item is and address
                    item += ")"  # add closing bracket
                    addresses.append(item)  # put in address list
                else:
                    # item is command
                    instruction = item

            instruction = bytes(instruction.encode('utf-8'))

            for addr in addresses:  # for every address selected
                addr = ast.literal_eval(addr)  # turn string to tuple
                server.send_to_one(addr, instruction)  # send instruction to address

        except IndexError:
            print('Invalid input')
        except KeyboardInterrupt:
            sys.exit(0)
        except SyntaxError:
            # invalid input for ast.literal_eval so just pass
            pass


def many_to_many_mode():
    """
    many commands are sent to many machines. (All commands --> all machines)

    e.g.

    address1, address2, command, different_command

    command --> address1

    different_command --> address 1


    command --> address2

    different_command --> address 2
    """

    while True:
        try:
            command = input("m-m$ ")
            if "exit" in command:
                break
            command = command.split(") ")  # split at every closing bracket
            addresses = []
            instruction = []
            for item in command:
                if item[0] == "(":
                    # item is and address
                    item += ")"  # add closing bracket
                    addresses.append(item)  # put in address list
                else:
                    # item is command
                    instruction.append(item)

            instruction = instruction[0].split()

            for addr in addresses:  # for every address selected
                addr = ast.literal_eval(addr)  # turn string to tuple
                for instr in instruction:
                    server.send_to_one(addr, bytes(instr.encode('utf-8')))
                    time.sleep(0.2)

        except IndexError:
            print('Invalid input')
        except KeyboardInterrupt:
            sys.exit(0)
        except SyntaxError:
            # invalid input for ast.literal_eval so just pass
            pass


def main():
    # start a thread for server
    server_thread = threading.Thread(target=server.listen)  # create a thread to listen for connections
    server_thread.start()
    time.sleep(0.3)  # give some time for threads to start

    # accept user input

    while True:
        try:
            command = input("$ ")
            if "1-1" in command:
                one_to_one_mode()  # one command --> one address
            elif "m-1" in command:
                many_to_one_mode()  # many commands --> one address
            elif "1-m" in command:
                one_to_many_mode()  # one command --> many addresses
            elif "m-m" in command:
                many_to_many_mode()  # many commands --> many addresses

        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    server = Server("127.0.0.1", 6969, 2048)
    main()