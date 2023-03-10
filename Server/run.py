from Server import Server
import socket

server = Server(socket.AF_INET, socket.SOCK_STREAM)
server.listen()