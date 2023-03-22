import socket
import threading
import sys
from os.path import exists
from os import system, _exit, makedirs, stat
from config import *
from encryptor import *
import hashlib


class FileHandler(socket.socket):
    """
    This is a client FTP class for sending files.
    I use 2 separate sockets for transferring messages and files, so there are no
    conflicts and both data can be sent independently in the same time.
    At the begging, client sends his nickname.
    Transferring 1 file takes 3 steps:
    1) Send name of the file
    2) Keep sending chunks of specified size *[1]
    3) Send the last chunk and mark it
    4) Send sha256 hash and compare it to generated

    [1] Chunk size is specified manually in the both sides, it isn't transferred.
    Each chunk of data starts with 0 or 1, 0 means this chunk isn't the last one,
    1 means it is the last. If the chunk is the last, it means that it is filled up
    with spaces at the end which must not be considered as the actual data.
    """

    def __init__(self, *args, addr, client) -> None:
        super().__init__(*args)
        self.setblocking(True)
        self.encryptor = Encryptor()
        self.encryptor.generate_key()
        self.decryptor = Encryptor()
        self.decryptor.key = [self.encryptor.key,
                              self.encryptor.nonce]
        addr[1] = int(addr[1])
        try:
            super().connect(tuple(addr))
        except:
            print(
                "File socket connection failed. Try to reconnect if you want to send or receive files")
            self.connected = False
            return
        else:
            self.connected = True

        print("Establishing secure connection for file transfer...")
        public_key = super().recv(251)
        self.encryptor.public_key = rsa.PublicKey.load_pkcs1(public_key)
        key = self.encryptor.encrypt_rsa(self.encryptor.key)
        super().send(key)
        nonce = self.encryptor.encrypt_rsa(self.encryptor.nonce)
        super().send(nonce)

        status = super().recv(9)
        status = self.decryptor.decrypt(status).decode()
        if status != "[SUCCESS]":
            print("Failed to establish secure connection.")
            _exit(0)
        print(status)
        print("Secure connection for file transfer established.")

        self.client = client
        makedirs(DOWNLOADS_FOLDER_NAME) if not exists(
            DOWNLOADS_FOLDER_NAME) else None

        nick_len = str(len(self.client.nickname.encode())).encode()
        nick_len = nick_len+b" "*(HEADER-len(nick_len))
        nickname = self.client.nickname.encode()
        super().send(self.encryptor.encrypt(nick_len))
        super().send(self.encryptor.encrypt(nickname))

        self.recv_thread = threading.Thread(
            target=self.receive, name="file_sock")
        self.recv_thread.daemon = True
        self.recv_thread.start()

    def send(self, file):
        if not self.connected:
            print("Sorry, file socket is not connected.")
            return

        if not exists(file):
            print(
                f"Cant find file {file}, put it in the same directory or specify the whole path.")
            return
        if self.is_empty(file):
            print("Cant send empty file.")
            return

        file_name_len = str(len(file.encode())).encode()
        file_name_len += b" "*(HEADER-len(file_name_len))
        super().send(self.encryptor.encrypt(file_name_len))
        super().send(self.encryptor.encrypt(file.encode()))

        with open(file, "rb") as f:

            prefix = b"0"
            while chunk := f.read(FILE_CHUNK_SIZE-len(prefix)):
                postfix = b" "*(FILE_CHUNK_SIZE-(len(prefix)+len(chunk)))
                if len(postfix) > 0:
                    prefix = b"1"
                data = self.encryptor.encrypt(prefix+chunk+postfix)
                super().send(data)

        with open(file, "rb") as f:
            digest = hashlib.file_digest(f, "sha256")

        digest = self.encryptor.encrypt(digest.digest())
        super().send(digest)

    def is_empty(self, file):
        return stat(file).st_size == 0

    def receive(self):
        if not self.connected:
            print("Sorry, file socket is not connected.")
            return
        while 1:
            name_len = int(self.decryptor.decrypt(self.recv(HEADER)).decode())
            name = self.decryptor.decrypt(self.recv(name_len)).decode()
            with open(DOWNLOADS_FOLDER_NAME+"\\"+name, "wb") as file:
                while 1:
                    chunk = self.decryptor.decrypt(self.recv(FILE_CHUNK_SIZE))
                    status = chunk[0:1].decode()
                    if status == "1":
                        file.write(chunk[1:].rstrip(b"\x20"))

                        break
                    else:
                        file.write(chunk[1:])

            # sha256 hash is 32 bytes long
            server_digest = self.decryptor.decrypt(super().recv(32))
            with open(DOWNLOADS_FOLDER_NAME+"\\"+name, "rb") as f:
                digest = hashlib.file_digest(f, "sha256").digest()
            if digest == server_digest:
                print("File hashes match!")
            else:
                print("FILES HASHES DO NOT MATCH!")


class Client(socket.socket):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.setblocking(True)
        threading.excepthook = self.handle_disconnect

        self.files_queue = []
        self.encryptor = Encryptor()
        self.encryptor.generate_key()
        self.decryptor = Encryptor()
        self.decryptor.key = [self.encryptor.key,
                              self.encryptor.nonce]

    def connect_and_start(self, addr):
        print("Connecting...")
        try:
            super().connect(addr)
        except:
            print("Failed to connect")
            exit()
        self.conn = self
        print("Connected.")

        print("Waiting for establishing secure connection...")
        # RSA public key is 251 bytes
        public_key = super().recv(251)
        self.encryptor.public_key = rsa.PublicKey.load_pkcs1(public_key)
        key = self.encryptor.encrypt_rsa(self.encryptor.key)
        super().send(key)
        nonce = self.encryptor.encrypt_rsa(self.encryptor.nonce)
        super().send(nonce)

        status = super().recv(9)
        status = self.decryptor.decrypt(status).decode()
        print(status)
        if status != "[SUCCESS]":
            print("Failed to establish secure connection.")
            _exit(0)
        print("Secure connection established.")

        self.recv_thread = threading.Thread(target=self.receive, args=())
        self.recv_thread.start()

        self.send_thread = threading.Thread(
            target=self.read_input_and_send, args=())
        self.send_thread.daemon = True
        self.send_thread.start()

        self.sending_files_thread = threading.Thread(target=self.send_files)
        self.sending_files_thread.daemon = True
        self.sending_files_thread.start()

    def handle_disconnect(self, args):
        errors = [ConnectionResetError,
                  ConnectionAbortedError,
                  ConnectionError,
                  ConnectionRefusedError]
        if args.exc_type in errors:
            if args.thread.name != "file_sock":
                print(
                    f"Connection lost. (err code {errors.index(args.exc_type)})")
        else:
            sys.__excepthook__(
                args.exc_type, args.exc_value, args.exc_traceback)

    def read_input_and_send(self):

        while 1:
            msg = input("Enter msg:")
            if msg[:11] == r"/send_files":
                if not (msg[11:].replace(" ", "")):
                    print(
                        "Please specify file or files to send. \nfor example: /send file f.txt, img.png")
                    continue
                sending_thread = threading.Thread(
                    target=self.send_file_command, args=(msg[11:],))
                sending_thread.daemon = True
                sending_thread.start()
            elif msg == "/exit" or msg == "/quit":
                _exit(0)
            elif msg[:9] == "/get_file" and not self.file_handler.connected:
                print("Sorry, file socket is not connected.")

            else:
                self.send(msg)

    def receive(self):

        while 1:

            msg_len = super().recv(HEADER)
            msg_len = self.decryptor.decrypt(msg_len)
            msg_len = msg_len.decode()

            if not msg_len:
                print("Empty length received, something went wrong. Exiting...")
                _exit(1)

            msg_len = int(msg_len)
            msg = super().recv(msg_len)
            msg = self.decryptor.decrypt(msg).decode()

            if msg.startswith("[nickname]"):
                self.nickname = msg.replace("[nickname]", "")
                system(f"title {self.nickname}")
            elif msg.startswith("[!FILESOCKET]"):
                addr = msg[13:].split("|")
                self.file_handler = FileHandler(
                    socket.AF_INET, socket.SOCK_STREAM, addr=addr, client=self)
            else:
                print(msg)

    def send(self, msg):
        # IMPORTANT! It is necessary to encrypt msg length before msg
        # because of the AES-CTR counters, I spent 3 hours
        # trying to fix this bug, please pay attention to it.
        if not msg.replace(" ", ""):
            return

        msg_len = str(len(msg.encode()))
        msg_len = msg_len.encode()+b" "*(HEADER-len(msg_len))
        msg_len = self.encryptor.encrypt(msg_len)
        super().send(msg_len)

        msg = self.encryptor.encrypt(msg.encode())
        super().send(msg)

    def send_file_command(self, param):
        if "," in param:
            files = param.replace(" ", "").split(",")
        else:
            files = param.split()

        self.files_queue.extend(files)

    def send_files(self):

        while 1:
            for file in self.files_queue:
                print("Sending", file)
                self.file_handler.send(file)
                self.files_queue.remove(file)


if __name__ == "__main__":
    client = Client(socket.AF_INET, socket.SOCK_STREAM)
    client.connect_and_start(ADDR)
