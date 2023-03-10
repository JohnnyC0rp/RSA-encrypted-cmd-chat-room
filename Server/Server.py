import socket
import threading
from config import *
import csv
import sys
from os import makedirs, path
from encryptor import *
import hashlib


class FileSocket(socket.socket):
    """
    This is a server FTP class for sending files.
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

    def __init__(self, *args, server) -> None:
        super().__init__(*args)
        self.server = server
        self.clients = {}
        self.file_sock_encryptors = {}
        # This is a global encryptor, just loads rsa public key
        self.encryptor = Encryptor()
        self.encryptor.load_rsa_keys()
        self.public_key = self.encryptor.public_key.save_pkcs1("PEM")

        makedirs(DOWNLOADS_FOLDER_NAME) if not path.exists(
            DOWNLOADS_FOLDER_NAME) else None

        self.bind(FILE_ADDR)
        self.setblocking(True)

    def listen(self):
        super().listen()

        while 1:
            conn, addr = self.accept()
            thread = threading.Thread(target=self.handle_client,
                                      args=(conn, addr), name="f_sock")
            thread.start()

    def handle_client(self, conn, addr):

        # local encryptors (handle symmetric encryption)
        encryptor = Encryptor()
        decryptor = Encryptor()
        decryptor.load_rsa_keys()
        self.file_sock_encryptors[conn] = encryptor

        conn.send(self.public_key)

        # RSA key length is 1024 so each message is 1024/8 = 128 bytes
        key = conn.recv(128)
        nonce = conn.recv(128)
        decryptor.key = [decryptor.decrypt_rsa(key),
                         decryptor.decrypt_rsa(nonce)]
        encryptor.key = [decryptor.key,
                         decryptor.nonce]
        success = encryptor.encrypt(b"[SUCCESS]")
        conn.send(success)

        nick_len = int(decryptor.decrypt(conn.recv(HEADER)).decode())
        nickname = decryptor.decrypt(conn.recv(nick_len)).decode()
        self.clients[nickname] = conn
        while 1:

            name_len = int(decryptor.decrypt(conn.recv(HEADER)).decode())
            name = decryptor.decrypt(conn.recv(name_len)).decode()

            self.server.send_to_all(f"{nickname} is sending {name} ...")

            with open(DOWNLOADS_FOLDER_NAME+"\\"+name, "wb") as file:
                while 1:
                    chunk = decryptor.decrypt(conn.recv(FILE_CHUNK_SIZE))
                    status = chunk[0:1].decode()
                    if status == "1":
                        file.write(chunk[1:].rstrip(b"\x20"))
                        break
                    else:
                        file.write(chunk[1:])

            # sha256 hash is 32 bytes long
            client_digest = decryptor.decrypt(conn.recv(32))
            with open(DOWNLOADS_FOLDER_NAME+"\\"+name, "rb") as f:
                digest = hashlib.file_digest(f, "sha256").digest()
            if digest == client_digest:
                print("Hashes match!")
            else:
                self.server.send(conn, "ATTENTION! HASHES FOR FILES DO NOT MATCH! RESEND FILE!",
                                 self.server.encryptors[self.server.clients[nickname]])

            self.server.send_to_all(
                f"{nickname} has sent file {name}. \n Use /get_file [file name] to download it, or /preview [file name] to preview")

    def send(self, nickname, file):
        conn = self.clients[nickname]
        encryptor = self.file_sock_encryptors[conn]
        main_conn = self.server.clients[nickname]
        if not path.exists(DOWNLOADS_FOLDER_NAME+"\\"+file):
            self.server.send(
                main_conn, f"Cant find file {file}, nobody hasn't sent it yet.", self.server.encryptors[main_conn])
            return

        self.server.send(
            main_conn, f"Sending you file {file}...", self.server.encryptors[main_conn])

        file_name_len = str(len(file.encode())).encode()
        file_name_len += b" "*(HEADER-len(file_name_len))
        conn.send(encryptor.encrypt(file_name_len))
        conn.send(encryptor.encrypt(file.encode()))

        with open(DOWNLOADS_FOLDER_NAME+"\\"+file, "rb") as f:

            prefix = b"0"
            while chunk := f.read(FILE_CHUNK_SIZE-len(prefix)):
                postfix = b" "*(FILE_CHUNK_SIZE-(len(prefix)+len(chunk)))
                if len(postfix) > 0:
                    prefix = b"1"
                data = encryptor.encrypt(prefix+chunk+postfix)
                conn.send(data)

        with open(DOWNLOADS_FOLDER_NAME+"\\"+file, "rb") as f:
            digest = hashlib.file_digest(f, "sha256")
        digest = encryptor.encrypt(digest.digest())
        conn.send(digest)

        self.server.send(
            main_conn, f"File {file} - sending finished.", self.server.encryptors[main_conn])


class Server(socket.socket):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Reading files
        self.f_bans = open("bans.txt", "a+")
        self.f_bans.seek(0)
        self.banned = self.f_bans.read().split(";")

        # Initializing vars
        self.history = []
        self.connections = []
        self.clients = {}
        self.encryptors = {}
        self.blocked = []
        self.help_msg = HELP
        self.receiving_files = {}
        # This is a global encryptor, just loads rsa public key
        self.encryptor = Encryptor()
        self.encryptor.load_rsa_keys()
        self.public_key = self.encryptor.public_key.save_pkcs1("PEM")

        self.bind(ADDR)
        self.setblocking(True)

        # File socket
        self.f_sock = FileSocket(
            socket.AF_INET, socket.SOCK_STREAM, server=self)
        self.f_sock_thread = threading.Thread(
            target=self.f_sock.listen, name="f_sock")
        self.f_sock_thread.start()

        threading.excepthook = self.handle_disconnect

    def listen(self):
        super().listen()
        print(f"Server is listening on {ADDR}")
        history_backup_thread = threading.Thread(target=self.save_history)
        history_backup_thread.daemon = True
        history_backup_thread.start()
        while 1:
            conn, addr = self.accept()
            thread = threading.Thread(target=self.handle_client,
                                      args=(conn, addr))
            thread.start()
            print(
                f"[NEW_CONNECTION] {(addr)} Now clients connected: {len(self.connections)+1}")

    def save_history(self):
        while 1:
            if len(self.history) > 50:
                with open("history.csv", "a", newline="") as file:
                    writer = csv.writer(file)
                    writer.writerows(self.history)
                self.history = []

    def send_history(self, conn, encryptor):
        if path.exists("history.csv"):
            with open("history.csv", "r") as file:
                reader = csv.reader(file)
                for line in reader:
                    self.send(conn, "".join(line), encryptor)
        # send history
        for line in self.history:
            self.send(conn, line, encryptor)

    def handle_client(self, conn, addr):
        threading.current_thread().addr = addr
        threading.current_thread().conn = conn

        ip, socket = addr
        is_admin = False

        # local encryptors (handle symmetric encryption)
        encryptor = Encryptor()
        decryptor = Encryptor()
        decryptor.load_rsa_keys()

        conn.send(self.public_key)

        # RSA key length is 1024 so each message is 1024/8 = 128 bytes
        key = conn.recv(128)
        nonce = conn.recv(128)
        decryptor.key = [decryptor.decrypt_rsa(key),
                         decryptor.decrypt_rsa(nonce)]
        encryptor.key = [decryptor.key,
                         decryptor.nonce]
        success = encryptor.encrypt(b"[SUCCESS]")
        conn.send(success)

        if ip in self.banned:
            self.send(conn, "You were banned.", encryptor)
            try:
                del self.encryptors[conn]
            except (KeyError, ValueError):
                pass
            conn.close()
            return

        self.send(
            conn, f"Enter nickname (these are already taken, don't use them ({list( self.clients.keys() )}) ):", encryptor)
        nickname = self.receive(conn, decryptor)

        if not nickname or len(nickname) > NICK_MAX_LEN:
            self.send(
                conn, f"Sorry, nickname must be from 1 to {NICK_MAX_LEN} chars long.", encryptor)
            conn.close()
            raise ConnectionAbortedError

        if nickname in self.clients:
            self.send(
                conn, f"Sorry, this nickname is already taken.", encryptor)
            conn.close()
            raise ConnectionAbortedError

        if "admin" in nickname:
            is_admin = self.check_admin(conn, decryptor, encryptor)
            if is_admin:
                print("Admin /|\ ")  # shows that above client is admin
            else:
                self.send(
                    conn, "Sorry, only admins can have 'admin' in nickname", encryptor)
                conn.close()
                raise ConnectionAbortedError

        self.encryptors[conn] = encryptor
        self.connections.append(conn)
        self.clients[nickname] = conn
        self.send(conn, f"[nickname]{nickname}", encryptor)
        self.send(
            conn, f"[!FILESOCKET]{FILE_ADDR[0]}|{FILE_ADDR[1]}", encryptor)
        threading.current_thread().nickname = nickname
        self.receiving_files[conn] = {}
        self.send_history(conn, encryptor)
        self.send_to_all(f"{nickname} joined!")

        while 1:
            msg = self.receive(conn, decryptor)

            if nickname in self.blocked:
                self.send(conn, "You are blocked now.", encryptor)
                continue
            # msg can be empty
            elif msg and msg.replace(" ", "") and msg.split()[0] in COMMANDS:

                # Accessing server __dict__ to run function for received command
                # Each such function has similar name with command and
                # kept in commands.py and takes 3 params:
                # additional command parameters in list, nickname, admin status

                func = Server.__dict__[msg.split()[0][1:]]
                func(self, msg.split()[1:], nickname, is_admin)

            elif msg:
                self.send_to_all(f"{nickname}: {msg}")

    def handle_disconnect(self, args):
        errors = [ConnectionResetError,
                  ConnectionAbortedError,
                  ConnectionError,
                  ConnectionRefusedError]
        if args.exc_type in errors:

            # only main client handler will raise forward actions, file handler won't
            if args.thread.name == "f_sock":
                return
            nickname = args.thread.nickname if "nickname" in args.thread.__dict__ else None
            conn = args.thread.conn
            addr = args.thread.addr
            print(
                f"Connection lost with client {nickname} ({addr}) (err code {errors.index(args.exc_type)})")
            try:
                self.connections.remove(conn)
                del self.encryptors[conn]
                del self.clients[nickname]
            except (ValueError, KeyError):  # conn is not in list, for example client hasn't sent nickname
                pass
            if nickname:
                self.send_to_all(f"{nickname} left.")

        else:
            sys.__excepthook__(
                args.exc_type, args.exc_value, args.exc_traceback)

    def send_to_all(self, msg):
        self.history.append(msg)
        for conn, encryptor in self.encryptors.items():
            self.send(conn, msg, encryptor)

    def check_admin(self, conn, decryptor, encryptor):
        self.send(conn, "Enter admin password: ", encryptor)
        password = self.receive(conn, decryptor)
        if password == ADMIN_PASS:
            self.send(conn, "ACCESS GRANTED", encryptor)
            return True
        else:
            self.send(conn, "ACCESS DENIED", encryptor)
            return False

    def send(self, conn, msg, encryptor):
        # IMPORTANT! It is necessary to encrypt msg length before msg
        # because of the AES-CTR counters, I spent 3 hours
        # trying to fix this bug, please pay attention to it.
        if not msg.replace(" ", ""):
            return

        msg_len = str(len(msg.encode()))
        msg_len = msg_len.encode()+b" "*(HEADER-len(msg_len))
        msg_len = encryptor.encrypt(msg_len)
        msg = encryptor.encrypt(msg.encode())

        conn.send(msg_len)
        conn.send(msg)

    def receive(self, conn, decryptor):
        msg_len = conn.recv(HEADER)
        msg_len = int(decryptor.decrypt(msg_len).decode())
        msg = conn.recv(msg_len)
        msg = decryptor.decrypt(msg).decode()
        return msg

    from commands import kick, help, ban, participants, block, unblock, get_file, preview, view_files


if __name__ == "__main__":
    server = Server(socket.AF_INET, socket.SOCK_STREAM)
    server.listen()
