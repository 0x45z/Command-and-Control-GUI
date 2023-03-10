import socket
import threading
import time
import sys
import ast
import tkinter as tk

print_lock = threading.Lock()


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

                # get index in dict of client as this will be the index of the button that needs to be removed
                address_list = list(server.clients.keys())
                index = address_list.index(self.address)

                # remove the button at that index in list
                button_to_remove = app.buttons[index]
                app.remove_client_button(button_to_remove)

                # adjust the position of all other buttons
                app.adjust_client_button_positions()

                server.remove_client(self.address)  # remove client from dict
                with print_lock:
                    print(f"Clients Connected: {server.num_client()}")
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
        print(f"[+] Server Listening on {self.ip}:{self.port}")

        try:
            while True:
                conn, address = self.socket.accept()
                print(f'Connection from {address}')
                client_thread = ClientHandler(conn, address, self.buffer)  # create a thread to handle individual client
                self.clients[address] = conn  # add the socket object to a dictionary with client address as key
                client_thread.start()
                print(f"Clients Connected: {len(self.clients)}")
                app.create_client_button(address)

        except KeyboardInterrupt:
            self.socket.close()
            sys.exit(0)

    def send_to_one(self, address, message):
        if address in self.clients:  # make sure client exists
            self.clients[address].send(message)  # send message using socket object
        else:
            print(f"Client {address} does not exist")
            for key in self.clients.keys():
                print(key, type(key))

    def remove_client(self, client):
        del self.clients[client]

    def num_client(self):
        return len(self.clients)


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
            print(commands)
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
                    time.sleep(2)

        except IndexError:
            print('Invalid input')
        except KeyboardInterrupt:
            sys.exit(0)
        except SyntaxError:
            # invalid input for ast.literal_eval so just pass
            pass


class App:
    def __init__(self, master):
        self.master = master

        # create a left frame with two columns
        self.left_frame = tk.Frame(self.master)
        self.left_frame.grid(row=0, column=0, rowspan=2, padx=10, pady=10, sticky="nsew")
        self.left_frame.columnconfigure(0, weight=1)
        self.left_frame.columnconfigure(1, weight=1)

        self.buttons = []  # client buttons list

        # command buttons
        self.button2 = tk.Button(self.left_frame, text="Get Processes")
        self.button2.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")

        self.button3 = tk.Button(self.left_frame, text="Get Network Info")
        self.button3.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")

        self.button4 = tk.Button(self.left_frame, text="Get Users")
        self.button4.grid(row=2, column=1, padx=5, pady=5, sticky="nsew")

        # create a canvas and text widget in the right frame
        self.right_frame = tk.Frame(self.master)
        self.right_frame.grid(row=0, column=1, rowspan=2, padx=10, pady=10, sticky="nsew")
        self.right_frame.columnconfigure(0, weight=1)
        self.right_frame.rowconfigure(1, weight=1)

        self.canvas = tk.Canvas(self.right_frame, width=600, height=400, bg="white")
        self.canvas.grid(row=0, column=0, sticky="nsew")

        self.text_widget = tk.Text(self.right_frame, width=40, height=10)
        self.text_widget.grid(row=0, column=0, sticky="nsew")

        # set the text widget to redirect stdout to the widget
        self.text_widget.tag_configure("stdout", foreground="black")
        sys.stdout = StdoutWriter(self.text_widget, "stdout")

        # set the closing event to run the on_closing function
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        sys.stdout = sys.__stdout__  # restore stdout
        self.master.destroy()  # close window

    def create_client_button(self, name):
        name = "".join(f"{name[0]}:{name[1]}")  # format client name to ip:port
        button = tk.Button(self.left_frame, text=str(name))  # create client button
        row_num = server.num_client() - 1  # get correct row based on number of connected clients
        button.grid(row=row_num, column=0, padx=5, pady=5, sticky="nsew")  # set it in correct place
        self.buttons.append(button)  # add button to buttons list

    def remove_client_button(self, button):
        # remove a client button
        button.destroy()
        self.buttons.remove(button)

    def adjust_client_button_positions(self):
        for i in range(len(self.buttons)):
            # make the row of the button that of the index of the button in the list
            self.buttons[i].grid(row=i, column=0, padx=5, pady=5, sticky="nsew")


class StdoutWriter:
    def __init__(self, text_widget, tag):
        self.text_widget = text_widget
        self.tag = tag

    def write(self, msg):
        # write stdout into tkinter widget
        self.text_widget.configure(state="normal")
        self.text_widget.insert("end", msg, (self.tag,))
        self.text_widget.configure(state="disabled")


if __name__ == "__main__":
    server = Server("127.0.0.1", 6969, 2048)
    root = tk.Tk()
    app = App(root)
    server_thread = threading.Thread(target=server.listen)  # create a thread to listen for connections
    server_thread.start()
    root.mainloop()