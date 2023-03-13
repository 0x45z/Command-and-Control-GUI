import socket
import threading
import time
import sys
import ast
import tkinter as tk
from tkinter import messagebox

print_lock = threading.Lock()


def safe_print(msg):
    """
    Prints using threading.Lock so that threads are not printing at the same time.

        Parameter:
            msg (str): text to print
    """
    with print_lock:
        print(msg)


class ClientHandler(threading.Thread):
    def __init__(self, socket, address, buffer):
        threading.Thread.__init__(self)
        self.socket = socket
        self.socket.settimeout(2)
        self.address = address
        self.buffer = buffer
        self.running = True

    def run(self):
        """
        Listens for messages from an individual client and cleans up if client disconnects.
        """
        # Listen for messages from client
        while self.running:
            try:
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
                    safe_print(f"\n[+] {self.address[0]}:{self.address[1]} says:\n{message}\n")
                if not message:
                    # Client has disconnected
                    safe_print(f'Client {self.address[0]}:{self.address[1]} Disconnected')

                    # get index in dict of client as this will be the index of the button that needs to be removed
                    address_list = list(server.clients.keys())
                    index = address_list.index(self.address)

                    # remove the button at that index in list
                    button_to_remove = app.buttons[index]
                    app.remove_client_button(button_to_remove)

                    # adjust the position of all other buttons
                    app.adjust_client_button_positions()

                    server.remove_client(self.address)  # remove client from dict

                    try:
                        app.selected_clients.remove(self.address)  # remove client from selected address list
                        app.process_commands_to_clients()  # update command widget so that disconnected client isn't
                        # shown
                    except ValueError:
                        # client not in list so just pass
                        pass

                    safe_print(f"Clients Connected: {server.num_client()}")
                    self.socket.close()  # close socket
                    break  # break out of while loop
            except socket.timeout:
                # socket time out (needed to stop thread)
                continue

    def send(self, message):
        """
        Encodes and sends a message to the client

            Parameter:
                message (str): Message to be sent to the client
        """
        self.socket.sendall(message.encode('utf-8'))

    def stop(self):
        """
        Sets the running variable to False.

        When the running variable is set to false, the loop in the run function, which is being executed by a thread,
        will end; thus stopping the thread and allowing the program to be successfully terminated.
        """
        self.running = False


class Server:
    def __init__(self, ip, port, buffer):
        self.ip = ip
        self.port = port
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # release socket after closed
        self.socket.settimeout(1)
        self.socket.bind((self.ip, self.port))
        self.clients = {}
        self.running = True
        self.stop_event = threading.Event()  # object to stop thread
        self.threads = []

    def listen(self):
        """
        Listens for and accepts connections from new clients.

        When a new client connects, the socket is appended to a list with the address of the client as a key. A thread
        is then started and runs the ClientHandler class to listen for messages from this client. A call to the
        create_client_button() function is made to create the client button.
        """
        self.socket.listen(20)
        safe_print(f"[+] Server Listening on {self.ip}:{self.port}")

        try:
            while self.running:
                try:
                    conn, address = self.socket.accept()
                    safe_print(f'Connection from {address[0]}:{address[1]}')
                    client_thread = ClientHandler(conn, address, self.buffer)  # create a thread to handle individual
                    # client
                    self.clients[address] = conn  # add the socket object to a dictionary with client address as key
                    client_thread.start()
                    self.threads.append(client_thread)
                    safe_print(f"Clients Connected: {len(self.clients)}")
                    app.create_client_button(address)
                except socket.timeout:
                    # continue looping if socket times out (needed to terminate thread)
                    continue
                except OSError:
                    # socket has been closed because stop() has been called
                    break

        except KeyboardInterrupt:
            self.socket.close()
            sys.exit(0)

    def send_to_one(self, address, message):
        """
        Sends a message to a client.
        
        The client socket is retrieved from the clients dictionary using the address as a key, this socket is then used
        to send the message.
        
            Parameters:
                address (tuple) Address of the client 
                message (str) Message to send to client
        """
        if address in self.clients:  # make sure client exists
            self.clients[address].send(message)  # send message using socket object
        else:
            safe_print(f"Client {address[0]}:{address[1]} does not exist")

    def remove_client(self, client):
        """
        Removes a client from the client dictionary.
        """
        del self.clients[client]

    def num_client(self):
        """
        Returns the number of clients connected.

            Returns:
                (int)
        """
        return len(self.clients)

    def get_clients(self):
        """
        Returns the addresses of the connected clients.

            Returns:
                (list)
        """
        return list(self.clients.keys())

    def stop(self):
        """
        Terminates all running threads.

        Sets the running flag to false to terminate the server thread, then calls the stop function in ClientHandler
        for every thread in the threads list to terminate all of those threads, then waits for them to finish
        executing.
        """
        self.running = False
        self.stop_event.set()  # signal thread to stop
        self.socket.close()  # close socket
        # stop all client handler threads
        for thread in self.threads:
            thread.stop()  # have the thread call the stop function
            thread.join()  # wait for thread to terminate


def one_to_one_mode(command):
    """
    Send one command to one client.

    Splits the command at ") " to separate the address from the actual command, turns the address from a string to a
    tuple so that the socket can be attained from the clients list, then encodes and sends the message to the
    send_to_one function in the Server class.

        Parameter:
            command (str): Address and command for client in the form: ('ip', port) command
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
        safe_print('Invalid input')
    except KeyboardInterrupt:
        sys.exit(0)
    except SyntaxError:
        # invalid input for ast.literal_eval so just pass
        pass


def multiple_one_to_ones(command):
    """
    Takes multiple commands and clients and sends the command to the corresponding client.

    Takes multiple commands and addresses and parses them to get the corresponding command for the address, then
    sends each to the one_to_one_mode() function.

        e.g. address2 command2 address4 command 1 --> address 2 command 2
                                                      address 4 command 1

        Parameter:
            command (str): multiple addresses and commands
    """
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
    One command is sent to many machines.

        Parameter:
            command (str): addresses and command
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
        safe_print('Invalid input')
    except KeyboardInterrupt:
        sys.exit(0)
    except SyntaxError:
        # invalid input for ast.literal_eval so just pass
        pass


def many_to_many_mode(command):
    """
    many commands are sent to many machines. (All commands --> all machines).

    All commands are sent to all machines.

    e.g.

    address1, address2, command, different_command

    command --> address1

    different_command --> address 1


    command --> address2

    different_command --> address 2

        Parameter:
            command (str): addresses and commands
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
        safe_print('Invalid input')
    except KeyboardInterrupt:
        sys.exit(0)
    except SyntaxError:
        # invalid input for ast.literal_eval so just pass
        pass


class App:
    def __init__(self, master):
        self.master = master
        self.master.title("Controller")
        self.master.resizable(False, False)
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

        self.terminate_button = tk.Button(self.left_frame, text="Terminate", command=self.terminate_button_click)
        self.terminate_button.grid(row=3, column=1, padx=5, pady=5, sticky="nsew")
        self.tbh = False  # button is not highlighted

        # Right frame

        self.right_frame = tk.Frame(self.master)
        self.right_frame.grid(row=0, column=1, rowspan=2, padx=10, pady=10, sticky="nsew")
        self.right_frame.columnconfigure(0, weight=1)
        self.right_frame.rowconfigure(1, weight=1)

        # canvas
        self.canvas = tk.Canvas(self.right_frame, width=800, height=600, bg="white")
        self.canvas.grid(row=0, column=0, sticky="nsew")

        # text widget to display output
        self.text_widget = tk.Text(self.right_frame, width=40, height=40)
        self.text_widget.grid(row=0, column=0, sticky="nsew")
        self.text_widget.tag_configure("stdout", foreground="black")
        sys.stdout = StdoutWriter(self.text_widget, "stdout")  # redirect stdout to text widget

        # scroll bar for text widget
        self.scrollbar = tk.Scrollbar(self.right_frame)
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.text_widget.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.text_widget.yview)

        # Third frame

        self.third_frame = tk.Frame(self.master)
        self.third_frame.grid(row=0, column=2, rowspan=2, padx=10, pady=10, sticky="nsew")
        self.third_frame.columnconfigure(0, weight=1)
        self.third_frame.columnconfigure(1, weight=1)
        self.third_frame.rowconfigure(1, weight=1)

        # execute button
        self.execute_button = tk.Button(self.third_frame, text="Execute", fg="green",
                                        command=self.send_commands)
        self.execute_button.grid(row=4, column=0, padx=5, pady=5, sticky="nsew")

        # clear output button
        self.clear_button = tk.Button(self.third_frame, text="Clear Output", fg="red", command=self.clear_output)
        self.clear_button.grid(row=3, column=0, padx=5, pady=5, sticky="nsew")

        # command output
        self.command_canvas = tk.Canvas(self.third_frame, width=200, height=300, bg="white")
        self.command_canvas.grid(row=0, column=0, sticky="nsew")

        self.command_widget = tk.Text(self.third_frame, width=40, height=10)
        self.command_widget.grid(row=0, column=0, sticky="nsew")
        self.command_widget.config(state="disabled")

        # ip entry form
        self.ip_entry = tk.Entry(self.third_frame, width=10)
        self.ip_entry.grid(row=2, column=0, sticky="ew")

        # port entry form
        self.port_entry = tk.Entry(self.third_frame, width=10)
        self.port_entry.grid(row=2, column=1, sticky="ew")

        # set address button
        self.set_address_button = tk.Button(self.third_frame, text="Set", command=self.set_address)
        self.set_address_button.grid(row=2, column=2, sticky='ew')

        # set the closing event to run the on_closing function
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def set_address(self):
        """
        Sets the new address of the server.

        Takes the ip and the port from the entry boxes and ensures the server can be assigned this address, if not
        message boxes will appear with the error.

        Otherwise, all threads will be terminated, client buttons removed and output cleared. The Server class is then
        with this new address and the server thread is started.
        """

        # read inputs and error checking
        try:
            ip = self.ip_entry.get()  # get ip
            port = int(self.port_entry.get())  # get port
            test_server = Server(ip, port, 2048)

        except ValueError:
            # port is not a number
            messagebox.showerror('Error', 'Port is not a number')
            return
        except socket.gaierror:
            # invalid IP
            messagebox.showerror('Error', 'Invalid IP')
            return
        except OverflowError:
            # invalid port number 0-65535
            messagebox.showerror('Error', 'Invalid port number')
            return
        except OSError:
            # cannot assign address
            messagebox.showerror('Error', 'Cannot assign address')
            return

        del test_server

        # use global vars
        global server
        global server_thread

        # stop all threads
        server.stop()  # stop server thread
        server_thread.join()  # wait for it to finish

        # remove client buttons
        while self.buttons:
            for button in self.buttons:
                self.remove_client_button(button)  # remove all client buttons

        # clear output
        self.clear_output()  # clear screen output
        self.display_on_command_widget('')  # clear command output

        # set new address
        server = Server(ip, port, 2048)  # change server address
        server_thread = threading.Thread(target=server.listen)

        server_thread.start()  # restart server thread

    def clear_output(self):
        """
        Clears the output of the text widget.
        """
        self.text_widget.config(state="normal")  # set state to normal so it can be edited
        self.text_widget.delete("1.0", "end")  # clear
        self.text_widget.config(state="disabled")  # set state back to disabled

    def display_on_command_widget(self, msg):
        """
        Clears the command widget and displays the new command on it.

            Parameter:
                msg (str): The verbose command to be displayed on the widget.
        """
        self.command_widget.config(state="normal")  # set state to normal so it can be edited
        self.command_widget.delete("1.0", tk.END)  # clear
        self.command_widget.insert(tk.END, msg)  # insert message
        self.command_widget.config(state="disabled")  # disable interaction

    def proc_button_click(self):
        """
        Sets the Process button animation and adds/removes the command from the selected commands.

        Sets the button to either pressed or unpressed and will add the 'get_processes' command to the selected commands
        if the button is pressed, or remove it if the button is unpressed. The process_commands_to_clients() function
        is then called to display the verbose command to the user.
        """
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
        """
        Sets the Network button animation and adds/removes the command from the selected commands.

        Sets the button to either pressed or unpressed and will add the 'get_network' command to the selected commands
        if the button is pressed, or remove it if the button is unpressed. The process_commands_to_clients() function
        is then called to display the verbose command to the user.
        """
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
        """
        Sets the Users button animation and adds/removes the command from the selected commands.

        Sets the button to either pressed or unpressed and will add the 'get_users' command to the selected commands
        if the button is pressed, or remove it if the button is unpressed. The process_commands_to_clients() function
        is then called to display the verbose command to the user.
        """
        if not self.ubh:  # clicked for first time (add command)
            self.users_button.configure(relief=tk.SUNKEN)  # press
            self.ubh = True
            self.selected_commands.append('get_users')
        else:  # clicked for second time (remove command)
            self.users_button.configure(relief=tk.RAISED)  # un-press
            self.ubh = False
            self.selected_commands.remove('get_users')
        self.process_commands_to_clients()  # process and show user commands --> client info

    def terminate_button_click(self):
        """
        Sets the Terminate button animation and adds/removes the command from the selected commands.

        Sets the button to either pressed or unpressed and will add the 'terminate' command to the selected commands
        if the button is pressed, or remove it if the button is unpressed. The process_commands_to_clients() function
        is then called to display the verbose command to the user.
        """
        if not self.tbh:  # clicked for first time (add command)
            self.terminate_button.configure(relief=tk.SUNKEN)  # press
            self.tbh = True
            self.selected_commands.append('terminate')
        else:  # clicked for second time (remove command)
            self.terminate_button.configure(relief=tk.RAISED)
            self.tbh = False
            self.selected_commands.remove('terminate')
        self.process_commands_to_clients()

    def on_closing(self):
        """
        Exits the program when the 'x' on the gui is pressed.

        Stdout is restored, the gui window is removed, all threads are stopped and the program exits.
        """
        sys.stdout = sys.__stdout__  # restore stdout
        self.master.destroy()  # close window

        # stop all threads
        server.stop()  # stop server thread
        server_thread.join()  # wait for it to finish
        sys.exit(0)

    def create_client_button(self, name):
        """
        Creates a new client button.

        Creates a new button for the client, the row is selected from the number of clients - 1, the button is added to
        the buttons list and the button is set to not highlighted.

            Parameter:
                name (tuple): address of the client
        """
        name = "".join(f"{name[0]}:{name[1]}")  # format client name to ip:port
        button = tk.Button(self.left_frame, text=str(name), command=lambda: self.client_button_click(button))  # create
        # client button
        row_num = server.num_client() - 1  # get correct row based on number of connected clients
        button.grid(row=row_num, column=0, padx=5, pady=5, sticky="nsew")  # set it in correct place
        self.buttons.append(button)  # add button to buttons list
        self.highlighted_clients[button] = False  # add to dict that client button is not highlighted

    def remove_client_button(self, button):
        """
        Deletes client button and removes it from list.

            Parameter:
                button (tk.Button): button to me removed.
        """
        # remove a client button
        button.destroy()
        self.buttons.remove(button)

    def adjust_client_button_positions(self):
        """
        Runs when a client disconnects. The buttons position (row) is set to be that of it's index in the buttons list.
        """
        for i in range(len(self.buttons)):
            # make the row of the button that of the index of the button in the list
            self.buttons[i].grid(row=i, column=0, padx=5, pady=5, sticky="nsew")

    def client_button_click(self, button):
        """
        Runs when a client button is clicked.

        If the button is not already highlighted, the client's address is appended to the list of selected clients and
        the button is sunk. If the button is already highlighted, the client's address is removed from the list of
        selected clients and the button is raised.

            Parameter:
                button (tk.Button) client button that was clicked
        """
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
        """
        Runs after any of the client button(s) or the command buttons are clicked.

        Generates the real command (the one sent to the client) and the verbose command (the one displayed to the user
        in the command widget) based off of the buttons clicked and in what order. Also determines the command mode
        from the number of commands/clients.
        """
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

    def send_commands(self):
        """
        Sends the real command to one of the send functions based on the command mode.
        """
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
        """
        Writes stdout (print statements) to the text widget

            Parameter:
                msg (str): text to be displayed on widget.
        """
        # write stdout into tkinter widget
        self.text_widget.configure(state="normal")
        self.text_widget.insert("end", msg, (self.tag,))
        self.text_widget.see("end")  # automatically scroll to end
        self.text_widget.configure(state="disabled")


if __name__ == "__main__":
    server = Server("127.0.0.1", 1234, 2048)
    root = tk.Tk()
    app = App(root)
    server_thread = threading.Thread(target=server.listen)  # create a thread to listen for connections
    server_thread.start()
    root.mainloop()
