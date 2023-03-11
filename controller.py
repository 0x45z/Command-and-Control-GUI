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
                print(f"\n[+]{self.address} says:\n{message}")
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


def one_to_one_mode(command):
    """
    send one command to one client
    """

    try:
        command = command.split(") ", 1)
        addr = command[0]
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


def multiple_one_to_ones(command):
    commands = command.split(' ')  # split at every space
    counter = 0
    completed_commands = []
    for i in range(len(commands)):
        counter += 1
        if counter == 3:  # each command is split into 3 elements when splitting at spaces
            string = "".join(f"{commands[i - 2]} {commands[i - 1]} {commands[i]}")  # join elements together
            completed_commands.append(string)  # append completed command to list
            counter = 0  # reset counter
    for command in completed_commands:
        one_to_one_mode(command)
        time.sleep(0.15)


def one_to_many_mode(command):
    """
    One command is sent to many machines
    """

    try:
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


def many_to_many_mode(command):
    """
    many commands are sent to many machines. (All commands --> all machines)

    e.g.

    address1, address2, command, different_command

    command --> address1

    different_command --> address 1


    command --> address2

    different_command --> address 2
    """

    try:
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
        self.master.title("Controller")  # set window title
        self.master.resizable(False, False)  # window cant be resized
        self.buttons = []  # client buttons list
        self.selected_commands = []  # commands selected by user
        self.selected_clients = []  # clients selected by user
        self.highlighted_clients = {}  # a dictionary to represent if a client button is highlighted
        self.verbose_command = ""
        self.real_command = ""
        self.command_mode = ""

        # Left frame

        self.left_frame = tk.Frame(self.master)
        self.left_frame.grid(row=0, column=0, rowspan=2, padx=10, pady=10, sticky="nsew")
        self.left_frame.columnconfigure(0, weight=1)
        self.left_frame.columnconfigure(1, weight=1)

        # command buttons
        self.proc_button = tk.Button(self.left_frame, text="Get Processes", command=self.proc_button_click)
        self.proc_button.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        self.pbh = False  # proc button not highlighted

        self.net_button = tk.Button(self.left_frame, text="Get Network Info", command=self.net_button_click)
        self.net_button.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
        self.nbh = False  # net button not highlighted

        self.users_button = tk.Button(self.left_frame, text="Get Users", command=self.users_button_click)
        self.users_button.grid(row=2, column=1, padx=5, pady=5, sticky="nsew")
        self.ubh = False  # users button not highlighted

        # Right frame

        self.right_frame = tk.Frame(self.master)
        self.right_frame.grid(row=0, column=1, rowspan=2, padx=10, pady=10, sticky="nsew")
        self.right_frame.columnconfigure(0, weight=1)
        self.right_frame.rowconfigure(1, weight=1)

        self.canvas = tk.Canvas(self.right_frame, width=800, height=600, bg="white")
        self.canvas.grid(row=0, column=0, sticky="nsew")

        self.text_widget = tk.Text(self.right_frame, width=40, height=40)
        self.text_widget.grid(row=0, column=0, sticky="nsew")

        self.text_widget.tag_configure("stdout", foreground="black")
        sys.stdout = StdoutWriter(self.text_widget, "stdout")  # redirect stdout to text widget

        # Third frame

        self.third_frame = tk.Frame(self.master)
        self.third_frame.grid(row=0, column=2, rowspan=2, padx=10, pady=10, sticky="nsew")
        self.third_frame.columnconfigure(0, weight=1)
        self.third_frame.columnconfigure(1, weight=1)
        self.third_frame.rowconfigure(1, weight=1)

        self.execute_button = tk.Button(self.third_frame, text="Execute", fg="green",
                                        command=self.send_commands)
        self.execute_button.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")

        self.command_canvas = tk.Canvas(self.third_frame, width=200, height=300, bg="white")
        self.command_canvas.grid(row=0, column=0, sticky="nsew")

        self.command_widget = tk.Text(self.third_frame, width=40, height=10)
        self.command_widget.grid(row=0, column=0, sticky="nsew")

        # set the closing event to run the on_closing function
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def display_on_command_widget(self, msg):
        self.command_widget.delete("1.0", tk.END)  # clear text widget
        self.command_widget.insert(tk.END, msg)  # write message to end of text widget

    def proc_button_click(self):
        if not self.pbh:  # clicked for first time (add command)
            self.proc_button.configure(relief=tk.SUNKEN)  # press
            self.pbh = True
            self.selected_commands.append('get_processes')
        else:  # clicked for second time (remove command)
            self.proc_button.configure(relief=tk.RAISED)  # un-press
            self.pbh = False
            self.selected_commands.remove('get_processes')
        self.process_commands_to_clients()  # process and show user commands --> client info

    def net_button_click(self):
        if not self.nbh:  # clicked for first time (add command)
            self.net_button.configure(relief=tk.SUNKEN)  # press
            self.nbh = True
            self.selected_commands.append('get_network')
        else:  # clicked for second time (remove command)
            self.net_button.configure(relief=tk.RAISED)  # un-press
            self.nbh = False
            self.selected_commands.remove('get_network')
        self.process_commands_to_clients()  # process and show user commands --> client info

    def users_button_click(self):
        if not self.ubh:  # clicked for first time (add command)
            self.users_button.configure(relief=tk.SUNKEN)  # press
            self.ubh = True
            self.selected_commands.append('get_users')
        else:  # clicked for second time (remove command)
            self.users_button.configure(relief=tk.RAISED)  # un-press
            self.ubh = False
            self.selected_commands.remove('get_users')
        self.process_commands_to_clients()  # process and show user commands --> client info

    def on_closing(self):
        sys.stdout = sys.__stdout__  # restore stdout
        self.master.destroy()  # close window

    def create_client_button(self, name):
        name = "".join(f"{name[0]}:{name[1]}")  # format client name to ip:port
        button = tk.Button(self.left_frame, text=str(name), command=lambda: self.client_button_click(button))  # create
        # client button
        row_num = server.num_client() - 1  # get correct row based on number of connected clients
        button.grid(row=row_num, column=0, padx=5, pady=5, sticky="nsew")  # set it in correct place
        self.buttons.append(button)  # add button to buttons list
        self.highlighted_clients[button] = False  # add to dict that client button is not highlighted

    def remove_client_button(self, button):
        # remove a client button
        button.destroy()
        self.buttons.remove(button)

    def adjust_client_button_positions(self):
        for i in range(len(self.buttons)):
            # make the row of the button that of the index of the button in the list
            self.buttons[i].grid(row=i, column=0, padx=5, pady=5, sticky="nsew")

    def client_button_click(self, button):
        if not self.highlighted_clients[button]:
            # append client address to selected clients list when their button is pressed
            addr_list = list(server.clients.keys())  # get addresses of clients
            index = self.buttons.index(button)  # get the index of button in button list (this will be the same as index
            # in client list)
            addr = addr_list[index]  # get address using index from addresses in server.clients
            self.selected_clients.append(addr)  # append address to list
            button.configure(relief=tk.SUNKEN)  # sink button
            self.highlighted_clients[button] = True  # button is highlighted (sunk)
        else:
            # remove client address from selected clients list when their button is unpressed
            addr_list = list(server.clients.keys())  # get addresses of clients
            index = self.buttons.index(button)  # get the index of button in button list (this will be the same as index
            # in client list)
            addr = addr_list[index]  # get address using index from addresses in server.clients
            self.selected_clients.remove(addr)
            button.configure(relief=tk.RAISED)  # raise button
            self.highlighted_clients[button] = False  # button is not highlighted (sunk)
        self.process_commands_to_clients()  # process and show user commands --> client info

    def process_commands_to_clients(self):
        # either 1 command to multiple clients or multiple commands to multiple clients as 1-1 or all-all
        self.verbose_command = ""  # clear
        self.real_command = ""  # clear

        if len(self.selected_commands) == 1:
            # 1 to ?
            if len(self.selected_clients) == 1:
                self.command_mode = "1-1"  # set command 1 to 1
            else:
                self.command_mode = "1-m"  # set command mode to 1 to multiple
            self.verbose_command += f"{self.selected_commands[0]}:"
            for client in self.selected_clients:
                self.real_command += f"{client} "  # add clients to real command
                client = "".join(f"{client[0]}:{client[1]}")
                self.verbose_command += f"\n    --> {client}"
            self.real_command += f"{self.selected_commands[0]}"  # add command to real command

        elif len(self.selected_commands) > 1:
            # multiple commands to multiple clients
            if len(self.selected_commands) == len(self.selected_clients):  # if there are same num of cmds and clients
                # multiple 1 --> 1 's e.g. get_proc --> 1, get_users --> 2 etc.
                # command is sent to the corresponding client of the same index (aka order in which they were clicked)
                self.command_mode = "m1-1"
                for i in range(len(self.selected_clients)):
                    client = "".join(f"{self.selected_clients[i][0]}:{self.selected_clients[i][1]}")  # format addr
                    self.verbose_command += f"{self.selected_commands[i]} --> {client}\n"
                    self.real_command += f"{self.selected_clients[i]} {self.selected_commands[i]} "  # add to real cmd

            else:
                # all --> all e.g. get_proc --> 1 and 2, get_users --> 1 and 2 etc.
                # all commands will be executed by all clients
                self.command_mode = "m-m"
                for command in self.selected_commands:
                    self.verbose_command += f"{command}:\n"
                    for client in self.selected_clients:
                        formatted_client = "".join(f"{client[0]}:{client[1]}")  # format addr
                        self.verbose_command += f"    --> {formatted_client}\n"

                for client in self.selected_clients:
                    self.real_command += f"{client} "
                for command in self.selected_commands:
                    self.real_command += f"{command} "

        self.display_on_command_widget(self.verbose_command)  # display on command widget
        print(f"\n{self.real_command}")

    def send_commands(self):
        # pass the command to the correct send function
        if self.command_mode == "1-m":
            # 1 command to many clients
            one_to_many_mode(self.real_command)
        elif self.command_mode == "m1-1":
            # multiple 1 to 1's
            multiple_one_to_ones(self.real_command)
        elif self.command_mode == "m-m":
            # many to many
            many_to_many_mode(self.real_command)
        elif self.command_mode == "1-1":
            one_to_one_mode(self.real_command)


class StdoutWriter:
    def __init__(self, text_widget, tag):
        self.text_widget = text_widget
        self.tag = tag

    def write(self, msg):
        # write stdout into tkinter widget
        self.text_widget.configure(state="normal")
        self.text_widget.insert("end", msg, (self.tag,))
        self.text_widget.see("end")  # automatically scroll to end
        self.text_widget.configure(state="disabled")


if __name__ == "__main__":
    server = Server("127.0.0.1", 6969, 2048)
    root = tk.Tk()
    app = App(root)
    server_thread = threading.Thread(target=server.listen)  # create a thread to listen for connections
    server_thread.start()
    root.mainloop()