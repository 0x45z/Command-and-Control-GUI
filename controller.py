import socket
import threading
import sys


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
                print(f"[+]{self.address} says: {message}")
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
        print('address =', address)
        if address in self.clients:  # make sure client exists
            self.clients[address].send(message)  # send message using socket object
        else:
            print(f"Client {address} does not exist")
            for key in self.clients.keys():
                print(key, type(key))

    def remove_client(self, client):
        del self.clients[client]

    def get_clients(self):
        for key in self.clients.keys():
            yield key


if __name__ == "__main__":
    server = Server("127.0.0.1", 6969, 2048)
    server.listen()